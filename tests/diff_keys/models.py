import uuid

from django.db import models

from pgcrypto import fields


class EncryptedDiff(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    CHOICES = (
        ('a', 'a'),
        (1, '1'),
    )
    sym_field = fields.CharPGPSymmetricKeyField(blank=True, null=True,
                                                choices=CHOICES, max_length=1)

    class Meta:
        """Sets up the meta for the test model."""
        app_label = 'diff_keys'
