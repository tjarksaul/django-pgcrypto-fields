import uuid

from django.db import models

from pgcrypto import fields


class EncryptedFKModel(models.Model):
    """Dummy model used to test FK decryption."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    fk_pgp_sym_field = fields.TextPGPSymmetricKeyField(blank=True, null=True)

    class Meta:
        """Sets up the meta for the test model."""
        app_label = 'tests'


class EncryptedModel(models.Model):
    """Dummy model used for tests to check the fields."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    email_pgp_sym_field = fields.EmailPGPSymmetricKeyField(blank=True, null=True)
    integer_pgp_sym_field = fields.IntegerPGPSymmetricKeyField(blank=True, null=True)
    pgp_sym_field = fields.TextPGPSymmetricKeyField(blank=True, null=True)
    date_pgp_sym_field = fields.DatePGPSymmetricKeyField(blank=True, null=True)
    datetime_pgp_sym_field = fields.DateTimePGPSymmetricKeyField(blank=True, null=True)
    time_pgp_sym_field = fields.TimePGPSymmetricKeyField(blank=True, null=True)
    decimal_pgp_sym_field = fields.DecimalPGPSymmetricKeyField(
        max_digits=8, decimal_places=2, null=True, blank=True
    )
    float_pgp_sym_field = fields.FloatPGPSymmetricKeyField(blank=True, null=True)

    fk_model = models.ForeignKey(
        EncryptedFKModel, blank=True, null=True, on_delete=models.CASCADE
    )

    class Meta:
        """Sets up the meta for the test model."""
        app_label = 'tests'


class EncryptedDateTime(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    value = fields.DateTimePGPSymmetricKeyField()


class RelatedDateTime(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    related = models.ForeignKey(
        EncryptedDateTime,
        on_delete=models.CASCADE,
        related_name='related')
    related_again = models.ForeignKey(
        EncryptedDateTime, null=True,
        on_delete=models.CASCADE, related_name='related_again'
    )
