from base64 import b64encode
from os import urandom

import redis
from django.conf import settings
from django.db.models.expressions import Col
from django.utils.functional import cached_property

from pgcrypto import (
    PGP_SYM_DECRYPT_SQL,
    PGP_SYM_ENCRYPT_SQL,
)


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


class PGPSymmetricKeyFieldMixin(PGPMixin):
    """PGP symmetric key encrypted field mixin for postgres."""
    encrypt_sql = PGP_SYM_ENCRYPT_SQL
    decrypt_sql = PGP_SYM_DECRYPT_SQL
    cast_type = 'TEXT'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = None  # todo: perhaps default key?

    def pre_save(self, model_instance, add):
        """Save the original_value."""
        key_id = getattr(model_instance, "pk")

        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("select key from key_store where id = %s::text", (key_id,))
            row = cursor.fetchone()
            if row is None:
                self.key = self.generate_key()
                r = redis.Redis(host='redis', port=6379, db=0) # todo: konfigurierbar
                r.set(str(key_id), self.key)
            else:
                self.key = row[0]

        return super(PGPSymmetricKeyFieldMixin, self).pre_save(model_instance, add)

    @staticmethod
    def generate_key():
        return b64encode(urandom(32)).decode('utf-8')

    def get_placeholder(self, value, compiler, connection):
        """Tell postgres to encrypt this field using PGP."""
        val = self.encrypt_sql.format(self.key)
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
