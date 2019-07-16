import queue
from base64 import b64encode
from os import urandom
from uuid import UUID

import redis
from django.conf import settings
from django.db.models.expressions import Col
from django.utils.functional import cached_property
from django.db.models.sql.subqueries import UpdateQuery

from pgcrypto import (
    PGP_SYM_DECRYPT_SQL,
    PGP_SYM_ENCRYPT_SQL,
)
from pgcrypto.constants import REDIS_HOST, REDIS_PORT


def get_setting(connection, key):
    """Get key from connection or default to settings."""
    if key in connection.settings_dict:
        return connection.settings_dict[key]
    else:
        return getattr(settings, key)


class DecryptedCol(Col):
    """Provide DecryptedCol support without using `extra` sql."""

    def __init__(self, alias, target, output_field=None):
        """Init the decryption."""
        self.target = target

        super(DecryptedCol, self).__init__(alias, target, output_field)

    def as_sql(self, compiler, connection):
        """Build SQL with decryption and casting."""
        sql, params = super(DecryptedCol, self).as_sql(compiler, connection)
        sql = self.target.get_decrypt_sql(connection) % (sql, self.alias, self.target.get_cast_sql())
        return sql, params


# class HashMixin:
#     """Keyed hash mixin.
#
#     `HashMixin` uses 'pgcrypto' to encrypt data in a postgres database.
#     """
#     encrypt_sql = None  # Set in implementation class
#
#     def __init__(self, original=None, *args, **kwargs):
#         """Tells the init the original attr."""
#         self.original = original
#
#         super(HashMixin, self).__init__(*args, **kwargs)
#
#     def pre_save(self, model_instance, add):
#         """Save the original_value."""
#         if self.original:
#             original_value = getattr(model_instance, self.original)
#             setattr(model_instance, self.attname, original_value)
#
#         return super(HashMixin, self).pre_save(model_instance, add)
#
#     def get_placeholder(self, value=None, compiler=None, connection=None):
#         """
#         Tell postgres to encrypt this field with a hashing function.
#
#         The `value` string is checked to determine if we need to hash or keep
#         the current value.
#
#         `compiler` and `connection` is ignored here as we don't need custom operators.
#         """
#         if value is None or value.startswith('\\x'):
#             return '%s'
#
#         return self.get_encrypt_sql(connection)
#
#     def get_encrypt_sql(self, connection):
#         """Get encrypt sql. This may be overidden by some implementations."""
#         return self.encrypt_sql


class PGPMixin:
    """PGP encryption for field's value.

    `PGPMixin` uses 'pgcrypto' to encrypt data in a postgres database.
    """
    encrypt_sql = None  # Set in implementation class
    decrypt_sql = None  # Set in implementation class
    cast_type = None

    def __init__(self, *args, **kwargs):
        """`max_length` should be set to None as encrypted text size is variable."""
        super().__init__(*args, **kwargs)

    def db_type(self, connection=None):
        """Value stored in the database is hexadecimal."""
        return 'bytea'

    def get_placeholder(self, value, compiler, connection):
        """Tell postgres to encrypt this field using PGP."""
        raise NotImplementedError('The `get_placeholder` needs to be implemented.')

    def pre_save(self, model_instance, add):
        """Save the original_value."""

        return super(PGPMixin, self).pre_save(model_instance, add)

    def get_cast_sql(self):
        """Get cast sql. This may be overidden by some implementations."""
        return self.cast_type

    def get_decrypt_sql(self, connection):
        """Get decrypt sql."""
        raise NotImplementedError('The `get_decrypt_sql` needs to be implemented.')

    def get_col(self, alias, output_field=None):
        """Get the decryption for col."""
        if output_field is None:
            output_field = self
        if alias != self.model._meta.db_table or output_field != self:
            return DecryptedCol(
                alias,
                self,
                output_field
            )
        else:
            return self.cached_col

    @cached_property
    def cached_col(self):
        """Get cached version of decryption for col."""
        return DecryptedCol(
            self.model._meta.db_table,
            self
        )


class Encryption:
    @classmethod
    def generate_key(cls):
        return b64encode(urandom(32)).decode('utf-8')


class PGPSymmetricKeyFieldMixin(PGPMixin):
    """PGP symmetric key encrypted field mixin for postgres."""
    encrypt_sql = PGP_SYM_ENCRYPT_SQL
    decrypt_sql = PGP_SYM_DECRYPT_SQL
    cast_type = 'TEXT'
    keys = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def pre_save(self, model_instance, add):
        """Save the original_value."""
        key_id = getattr(model_instance, "pk")

        # from django.db import connection
        # with connection.cursor() as cursor:
        #     print("trying to fetch key for %s", (key_id,))
        #     cursor.execute("select key from key_store where id = %s::text", (key_id,))
        #     row = cursor.fetchone()
        #     if row is None:
        #         print("no key found for %s. Creating new one", (key_id,))
        #         key = Encryption.generate_key()
        #         self.keys[key_id] = key
        #         r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
        #         r.set(str(key_id), key, nx=True)
        #     else:
        #         print("Loading key from %s", (key_id,))
        #         self.keys[key_id] = row[0]

        return super(PGPSymmetricKeyFieldMixin, self).pre_save(model_instance, add)

    def get_placeholder(self, value, compiler, connection):
        """Tell postgres to encrypt this field using PGP."""
        if compiler.query is UpdateQuery:
            print("update query")
        key_id = None
        if hasattr(compiler.query, 'objs'):
            # key = self.keys[compiler.query.objs[0].id]
            key_id = compiler.query.objs[0].pk
        elif hasattr(compiler.query, 'where'):
            for child in compiler.query.where.children:
                if child.lookup_name == 'exact':
                    if hasattr(child.lhs, 'field') and hasattr(child.lhs.field, 'name') and child.lhs.field.name == 'id':
                        key_id = child.rhs
                    elif hasattr(child.rhs, 'field') and hasattr(child.rhs.field, 'name') and child.rhs.field.name == 'id':
                        key_id = child.lhs
                    elif hasattr(child.lhs, '__name__') and child.lhs.__name__ == 'UUID':
                        # key = self.keys[child.lhs]
                        key_id = child.lhs
                    elif hasattr(child.rhs, '__name__') and child.rhs.__name__ == 'UUID':
                        # key = self.keys[child.rhs]
                        key_id = child.rhs
        if key_id is None:
            print("couldn't find key id!")

        try:
            key = self.keys[key_id]
        except:
            from django.db import connection
            with connection.cursor() as cursor:
                print("trying to fetch key for %s", (key_id,))
                cursor.execute("select key from key_store where id = %s::text", (key_id,))
                row = cursor.fetchone()
                if row is None:
                    print("no key found for %s. Creating new one", (key_id,))
                    key = Encryption.generate_key()
                    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
                    r.set(str(key_id), key, nx=True)
                else:
                    print("Loading key from %s", (key_id,))
                    key = row[0]
        self.keys[key_id] = key

        val = self.encrypt_sql.format(key)
        # del self.keys[key_id]
        return val

    def get_decrypt_sql(self, connection):
        """Get decrypt sql."""
        return self.decrypt_sql  # .format(self.key)


class DecimalPGPFieldMixin:
    """Decimal PGP encrypted field mixin for postgres."""
    cast_type = 'NUMERIC(%(max_digits)s, %(decimal_places)s)'

    def get_cast_sql(self):
        """Get cast sql."""
        return self.cast_type % {
            'max_digits': self.max_digits,
            'decimal_places': self.decimal_places
        }
