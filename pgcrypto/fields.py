from io import BytesIO

import redis
from django.db import models
from django.db.models.fields.files import (
    FieldFile,
    FileField,
    ImageField,
    ImageFieldFile
)
from django.urls import reverse

from pgcrypto import (
    PGP_SYM_ENCRYPT_SQL_WITH_NULLIF,
)
from pgcrypto.mixins import (
    DecimalPGPFieldMixin,
    PGPSymmetricKeyFieldMixin,
    Encryption)
from .constants import FETCH_URL_NAME, REDIS_HOST, REDIS_PORT
from .crypt import Cryptographer


class EmailPGPSymmetricKeyField(PGPSymmetricKeyFieldMixin, models.EmailField):
    """Email PGP symmetric key encrypted field."""


class IntegerPGPSymmetricKeyField(PGPSymmetricKeyFieldMixin, models.IntegerField):
    """Integer PGP symmetric key encrypted field."""
    encrypt_sql = PGP_SYM_ENCRYPT_SQL_WITH_NULLIF
    cast_type = 'INT4'


class TextPGPSymmetricKeyField(PGPSymmetricKeyFieldMixin, models.TextField):
    """Text PGP symmetric key encrypted field for postgres."""


class CharPGPSymmetricKeyField(PGPSymmetricKeyFieldMixin, models.CharField):
    """Char PGP symmetric key encrypted field for postgres."""


class DatePGPSymmetricKeyField(PGPSymmetricKeyFieldMixin, models.DateField):
    """Date PGP symmetric key encrypted field for postgres."""
    encrypt_sql = PGP_SYM_ENCRYPT_SQL_WITH_NULLIF
    cast_type = 'DATE'


class DateTimePGPSymmetricKeyField(PGPSymmetricKeyFieldMixin, models.DateTimeField):
    """DateTime PGP symmetric key encrypted field for postgres."""
    encrypt_sql = PGP_SYM_ENCRYPT_SQL_WITH_NULLIF
    cast_type = 'TIMESTAMP'


class DecimalPGPSymmetricKeyField(DecimalPGPFieldMixin,
                                  PGPSymmetricKeyFieldMixin, models.DecimalField):
    """Decimal PGP symmetric key encrypted field for postgres."""


class FloatPGPSymmetricKeyField(PGPSymmetricKeyFieldMixin, models.FloatField):
    """Float PGP symmetric key encrypted field for postgres."""
    encrypt_sql = PGP_SYM_ENCRYPT_SQL_WITH_NULLIF
    cast_type = 'DOUBLE PRECISION'


class TimePGPSymmetricKeyField(PGPSymmetricKeyFieldMixin, models.TimeField):
    """Float PGP symmetric key encrypted field for postgres."""
    encrypt_sql = PGP_SYM_ENCRYPT_SQL_WITH_NULLIF
    cast_type = 'TIME'


class EncryptedFile(BytesIO):
    def __init__(self, content, password):
        self.size = content.size
        BytesIO.__init__(self, Cryptographer.encrypted(password, content.file.read()))


class FileEncryptionMixin(object):
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
                self.key = Encryption.generate_key()
                r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
                r.set(str(key_id), self.key)
            else:
                self.key = row[0]

        return super(FileEncryptionMixin, self).pre_save(model_instance, add)

    def save(self, name, content, save=True):
        if self.key is None:
            key_id = getattr(self.instance, "pk")

            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("select key from key_store where id = %s::text", (key_id,))
                row = cursor.fetchone()
                if row is None:
                    self.key = Encryption.generate_key()
                    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
                    r.set(str(key_id), self.key)
                else:
                    self.key = row[0]

        return FieldFile.save(
            self,
            name,
            EncryptedFile(content, password=self.key),
            save=save
        )

    save.alters_data = True

    def _get_url(self):
        return "%s?id=%s" % (reverse(FETCH_URL_NAME, kwargs={
            "path": super(FileEncryptionMixin, self).url,
        }), str(self.instance.pk))

    url = property(_get_url)


class EncryptedFieldFile(FileEncryptionMixin, FieldFile):
    pass


class EncryptedImageFieldFile(FileEncryptionMixin, ImageFieldFile):
    pass


class EncryptedFileField(FileField):
    attr_class = EncryptedFieldFile


class EncryptedImageField(ImageField):
    attr_class = EncryptedImageFieldFile

    def update_dimension_fields(self, instance, force=False, *args, **kwargs):
        """
        Since we're encrypting the file, any attempts to force recalculation of
        the dimensions will always fail, resulting in a null value for height
        and width.  To avoid that, we just set force=False all the time and
        expect that if you want to change those values, you'll do it on your
        own.
        """
        ImageField.update_dimension_fields(
            self, instance, force=False, *args, **kwargs)
