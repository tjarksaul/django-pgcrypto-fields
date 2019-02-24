import uuid
from datetime import date, datetime
from decimal import Decimal
from unittest.mock import MagicMock

from django import VERSION as DJANGO_VERSION
from django.conf import settings
from django.db import connections, models, reset_queries
from django.test import TestCase
from incuna_test_utils.utils import field_names

from pgcrypto import fields
from .diff_keys.models import EncryptedDiff
from .factories import EncryptedFKModelFactory, EncryptedModelFactory
from .forms import EncryptedForm
from .models import EncryptedDateTime, EncryptedFKModel, \
    EncryptedModel, RelatedDateTime

PGP_FIELDS = (
    fields.EmailPGPSymmetricKeyField,
    fields.DatePGPSymmetricKeyField,
    fields.DateTimePGPSymmetricKeyField,
    fields.IntegerPGPSymmetricKeyField,
    fields.TextPGPSymmetricKeyField,
)


class TestPGPMixin(TestCase):
    multi_db = True
    """Test `PGPMixin` behave properly."""
    def test_check(self):
        """Assert `max_length` check does not return any error."""
        for field in PGP_FIELDS:
            with self.subTest(field=field):
                field.model = MagicMock()
                self.assertEqual(field(name='field').check(), [])

    def test_db_type(self):
        """Check db_type is `bytea`."""
        for field in PGP_FIELDS:
            with self.subTest(field=field):
                self.assertEqual(field().db_type(), 'bytea')


class TestEmailPGPMixin(TestCase):
    """Test emails fields behave properly."""
    def test_max_length_validator(self):
        """Check `MaxLengthValidator` is not set."""
        with self.subTest(field=fields.EmailPGPSymmetricKeyField):
            field_validated = fields.EmailPGPSymmetricKeyField().run_validators(value='value@value.com')
            self.assertEqual(field_validated, None)


class TestEncryptedTextFieldModel(TestCase):
    multi_db = True
    """Test `EncryptedTextField` can be integrated in a `Django` model."""
    model = EncryptedModel

    # You have to do it here or queries is empty
    settings.DEBUG = True

    def test_fields(self):
        """Assert fields are representing our model."""
        fields = field_names(self.model)
        expected = (
            'id',
            'email_pgp_sym_field',
            'integer_pgp_sym_field',
            'pgp_sym_field',
            'date_pgp_sym_field',
            'datetime_pgp_sym_field',
            'time_pgp_sym_field',
            'decimal_pgp_sym_field',
            'float_pgp_sym_field',
            'fk_model',
        )
        self.assertCountEqual(fields, expected)

    def test_value_returned_is_not_bytea(self):
        """Assert value returned is not a memoryview instance."""
        EncryptedModelFactory.create()

        instance = self.model.objects.get()
        self.assertIsInstance(instance.email_pgp_sym_field, str)
        self.assertIsInstance(instance.integer_pgp_sym_field, int)
        self.assertIsInstance(instance.pgp_sym_field, str)
        self.assertIsInstance(instance.date_pgp_sym_field, date)
        self.assertIsInstance(instance.datetime_pgp_sym_field, datetime)

    def test_value_pgp_sym(self):
        """Assert we can get back the decrypted value."""
        expected = 'bonjour'
        EncryptedModelFactory.create(pgp_sym_field=expected)

        instance = self.model.objects.get()
        value = instance.pgp_sym_field

        self.assertEqual(value, expected)

    def test_update_attribute_pgp_sym_field(self):
        """Assert pgp field can be updated through its attribute on the model."""
        expected = 'bonjour'
        instance = EncryptedModelFactory.create()
        instance.pgp_sym_field = expected
        instance.save()

        updated_instance = self.model.objects.get()
        self.assertEqual(updated_instance.pgp_sym_field, expected)

    def test_update_one_attribute(self):
        """Assert value are not overriden when updating one attribute."""
        expected = 'initial value'
        new_value = 'new_value'

        instance = EncryptedModelFactory.create(
            pgp_sym_field=expected,
        )
        instance.pgp_sym_field = new_value
        instance.save()

        updated_instance = self.model.objects.get()
        self.assertEqual(updated_instance.pgp_sym_field, new_value)

    def test_pgp_symmetric_key_negative_number(self):
        """Assert negative value is saved with an `IntegerPGPSymmetricKeyField` field."""
        expected = -1
        instance = EncryptedModelFactory.create(integer_pgp_sym_field=expected)

        self.assertEqual(instance.integer_pgp_sym_field, expected)

    def test_pgp_symmetric_key_date(self):
        """Assert date is save with an `DatePGPSymmetricKeyField` field."""
        expected = date.today()
        instance = EncryptedModelFactory.create(date_pgp_sym_field=expected)
        instance.refresh_from_db()  # Ensure the PGSQL casting works right

        self.assertEqual(instance.date_pgp_sym_field, expected)

        instance = EncryptedModel.objects.get(pk=instance.id)

        self.assertEqual(instance.date_pgp_sym_field, expected)

    def test_pgp_symmetric_key_date_form(self):
        """Assert form field and widget for `DateTimePGPSymmetricKeyField` field."""
        expected = date.today()
        instance = EncryptedModelFactory.create(date_pgp_sym_field=expected)
        instance.refresh_from_db()  # Ensure the PGSQL casting works right

        payload = {
            'date_pgp_sym_field': '08/01/2016'
        }

        form = EncryptedForm(payload, instance=instance)
        self.assertTrue(form.is_valid())

        cleaned_data = form.cleaned_data

        self.assertTrue(
            cleaned_data['date_pgp_sym_field'],
            date(2016, 8, 1)
        )

    def test_pgp_symmetric_key_datetime_form(self):
        """Assert form field and widget for `DateTimePGPSymmetricKeyField` field."""
        expected = datetime.now()
        instance = EncryptedModelFactory.create(datetime_pgp_sym_field=expected)
        instance.refresh_from_db()  # Ensure the PGSQL casting works right

        payload = {
            'datetime_pgp_sym_field': '08/01/2016 14:00'
        }

        form = EncryptedForm(payload, instance=instance)
        self.assertTrue(form.is_valid())

        cleaned_data = form.cleaned_data

        self.assertTrue(
            cleaned_data['datetime_pgp_sym_field'],
            datetime(2016, 8, 1, 14, 0, 0)
        )

    def test_pgp_symmetric_key_time(self):
        """Assert date is save with an `TimePGPSymmetricKeyField` field."""
        expected = datetime.now().time()
        instance = EncryptedModelFactory.create(time_pgp_sym_field=expected)
        instance.refresh_from_db()  # Ensure the PGSQL casting works right

        self.assertEqual(instance.time_pgp_sym_field, expected)

        instance = EncryptedModel.objects.get(pk=instance.id)

        self.assertEqual(instance.time_pgp_sym_field, expected)

    def test_pgp_symmetric_key_time_form(self):
        """Assert form field and widget for `TimePGPSymmetricKeyField` field."""
        expected = datetime.now().time()
        instance = EncryptedModelFactory.create(time_pgp_sym_field=expected)
        instance.refresh_from_db()  # Ensure the PGSQL casting works right

        payload = {
            'time_pgp_sym_field': '{}'.format(expected)
        }

        form = EncryptedForm(payload, instance=instance)
        self.assertTrue(form.is_valid())

        cleaned_data = form.cleaned_data

        self.assertTrue(
            cleaned_data['time_pgp_sym_field'],
            expected
        )

    def test_pgp_symmetric_key_date_lookups(self):
        """Assert lookups `DatePGPSymmetricKeyField` field."""
        EncryptedModelFactory.create(date_pgp_sym_field=date(2016, 7, 1))
        EncryptedModelFactory.create(date_pgp_sym_field=date(2016, 8, 1))
        EncryptedModelFactory.create(date_pgp_sym_field=date(2016, 9, 1))

        # EXACT
        self.assertEqual(
            1,
            EncryptedModel.objects.filter(
                date_pgp_sym_field__exact=date(2016, 8, 1)
            ).count()
        )
        self.assertEqual(
            0,
            EncryptedModel.objects.filter(
                date_pgp_sym_field__exact=date(2016, 8, 2)
            ).count()
        )

        # GT
        self.assertEqual(
            1,
            EncryptedModel.objects.filter(
                date_pgp_sym_field__gt=date(2016, 8, 1)
            ).count()
        )
        self.assertEqual(
            0,
            EncryptedModel.objects.filter(
                date_pgp_sym_field__gt=date(2016, 10, 1)
            ).count()
        )

        # GTE
        self.assertEqual(
            2,
            EncryptedModel.objects.filter(
                date_pgp_sym_field__gte=date(2016, 8, 1)
            ).count()
        )
        self.assertEqual(
            0,
            EncryptedModel.objects.filter(
                date_pgp_sym_field__gte=date(2016, 10, 1)
            ).count()
        )

        # LE
        self.assertEqual(
            1,
            EncryptedModel.objects.filter(
                date_pgp_sym_field__lt=date(2016, 8, 1)
            ).count()
        )
        self.assertEqual(
            0,
            EncryptedModel.objects.filter(
                date_pgp_sym_field__lt=date(2016, 6, 1)
            ).count()
        )

        # LTE
        self.assertEqual(
            2,
            EncryptedModel.objects.filter(
                date_pgp_sym_field__lte=date(2016, 8, 1)
            ).count()
        )
        self.assertEqual(
            0,
            EncryptedModel.objects.filter(
                date_pgp_sym_field__lte=date(2016, 6, 1)
            ).count()
        )

        # RANGE
        self.assertEqual(
            3,
            EncryptedModel.objects.filter(
                date_pgp_sym_field__range=[date(2016, 6, 1), date(2016, 11, 1)]
            ).count()
        )

        self.assertEqual(
            2,
            EncryptedModel.objects.filter(
                date_pgp_sym_field__range=[date(2016, 7, 1), date(2016, 8, 1)]
            ).count()
        )

        self.assertEqual(
            0,
            EncryptedModel.objects.filter(
                date_pgp_sym_field__range=[date(2016, 10, 2), None]
            ).count()
        )


    def test_pgp_symmetric_key_datetime_lookups(self):
        """Assert lookups `DateTimePGPSymmetricKeyField` field."""
        EncryptedModelFactory.create(datetime_pgp_sym_field=datetime(2016, 7, 1, 0, 0, 0))
        EncryptedModelFactory.create(datetime_pgp_sym_field=datetime(2016, 8, 1, 0, 0, 0))
        EncryptedModelFactory.create(datetime_pgp_sym_field=datetime(2016, 9, 1, 0, 0, 0))

        # EXACT
        self.assertEqual(
            1,
            EncryptedModel.objects.filter(
                datetime_pgp_sym_field__exact=datetime(2016, 8, 1, 0, 0, 0)
            ).count()
        )
        self.assertEqual(
            0,
            EncryptedModel.objects.filter(
                datetime_pgp_sym_field__exact=datetime(2016, 8, 1, 0, 0, 1)
            ).count()
        )

        # GT
        self.assertEqual(
            1,
            EncryptedModel.objects.filter(
                datetime_pgp_sym_field__gt=datetime(2016, 8, 1, 0, 0, 0)
            ).count()
        )
        self.assertEqual(
            0,
            EncryptedModel.objects.filter(
                datetime_pgp_sym_field__gt=datetime(2016, 10, 1, 0, 0, 0)
            ).count()
        )

        # GTE
        self.assertEqual(
            2,
            EncryptedModel.objects.filter(
                datetime_pgp_sym_field__gte=datetime(2016, 8, 1, 0, 0, 0)
            ).count()
        )
        self.assertEqual(
            0,
            EncryptedModel.objects.filter(
                datetime_pgp_sym_field__gte=datetime(2016, 10, 1, 0, 0, 0)
            ).count()
        )

        # LE
        self.assertEqual(
            1,
            EncryptedModel.objects.filter(
                datetime_pgp_sym_field__lt=datetime(2016, 8, 1, 0, 0, 0)
            ).count()
        )
        self.assertEqual(
            0,
            EncryptedModel.objects.filter(
                datetime_pgp_sym_field__lt=datetime(2016, 6, 1, 0, 0, 0)
            ).count()
        )

        # LTE
        self.assertEqual(
            2,
            EncryptedModel.objects.filter(
                datetime_pgp_sym_field__lte=datetime(2016, 8, 1, 0, 0, 0)
            ).count()
        )
        self.assertEqual(
            0,
            EncryptedModel.objects.filter(
                datetime_pgp_sym_field__lte=datetime(2016, 6, 1, 0, 0, 0)
            ).count()
        )

        # RANGE
        self.assertEqual(
            3,
            EncryptedModel.objects.filter(
                datetime_pgp_sym_field__range=[
                    datetime(2016, 6, 1, 0, 0, 0),
                    datetime(2016, 11, 1, 23, 59, 59)
                ]
            ).count()
        )

        self.assertEqual(
            2,
            EncryptedModel.objects.filter(
                datetime_pgp_sym_field__range=[
                    datetime(2016, 7, 1, 0, 0, 0),
                    datetime(2016, 8, 1, 0, 0, 0)
                ]
            ).count()
        )

        self.assertEqual(
            0,
            EncryptedModel.objects.filter(
                datetime_pgp_sym_field__range=[
                    datetime(2016, 10, 1, 0, 0, 1),
                    None
                ]
            ).count()
        )


    def test_decimal_pgp_sym_field(self):
        """Test DecimalPGPSymmetricKeyField."""
        expected = '100000.99'
        EncryptedModelFactory.create(decimal_pgp_sym_field=expected)

        instance = EncryptedModel.objects.get()

        self.assertIsInstance(
            instance.decimal_pgp_sym_field,
            Decimal
        )

        self.assertEqual(
            instance.decimal_pgp_sym_field,
            Decimal(expected)
        )

        items = EncryptedModel.objects.filter(decimal_pgp_sym_field__gte='100')

        self.assertEqual(
            1,
            len(items)
        )

        items = EncryptedModel.objects.filter(decimal_pgp_sym_field__gte='100001.00')

        self.assertEqual(
            0,
            len(items)
        )


    def test_pgp_symmetric_key_decimal_form(self):
        """Assert form field and widget for `DecimalPGPSymmetricKeyField` field."""
        expected = '100000.99'
        instance = EncryptedModelFactory.create(decimal_pgp_sym_field=expected)

        payload = {
            'decimal_pgp_sym_field': expected
        }

        form = EncryptedForm(payload, instance=instance)
        self.assertTrue(form.is_valid())

        cleaned_data = form.cleaned_data

        self.assertTrue(
            cleaned_data['decimal_pgp_sym_field'],
            Decimal(expected)
        )


    def test_float_pgp_sym_field(self):
        """Test FloatPGPSymmetricKeyField."""
        expected = float(1234.6788)
        EncryptedModelFactory.create(float_pgp_sym_field=expected)

        instance = EncryptedModel.objects.get()

        self.assertIsInstance(
            instance.float_pgp_sym_field,
            float
        )

        self.assertEqual(
            instance.float_pgp_sym_field,
            expected
        )

        items = EncryptedModel.objects.filter(float_pgp_sym_field__gte='100')

        self.assertEqual(
            1,
            len(items)
        )

        items = EncryptedModel.objects.filter(float_pgp_sym_field__gte='100001.00')

        self.assertEqual(
            0,
            len(items)
        )

    def test_pgp_symmetric_key_float_form(self):
        """Assert form field and widget for `FloatPGPSymmetricKeyField` field."""
        expected = '100000.99'
        instance = EncryptedModelFactory.create(float_pgp_sym_field=expected)

        payload = {
            'float_pgp_sym_field': expected
        }

        form = EncryptedForm(payload, instance=instance)
        self.assertTrue(form.is_valid())

        cleaned_data = form.cleaned_data

        self.assertTrue(
            cleaned_data['float_pgp_sym_field'],
            float(expected)
        )

    def test_null(self):
        """Assert `NULL` values are saved."""
        instance = EncryptedModel.objects.create()
        fields = field_names(self.model)
        fields.remove('id')

        for field in fields:
            with self.subTest(instance=instance, field=field):
                value = getattr(instance, field)
                self.assertEqual(
                    value,
                    None,
                    msg='Field {}, Value: {}'.format(field, value)
                )

    def test_defer(self):
        """Test defer() functionality."""
        expected = 'bonjour'
        EncryptedModelFactory.create(pgp_sym_field=expected)
        instance = self.model.objects.defer('pgp_sym_field').get()

        # Assert that accessing a field that is in defer() causes a query
        with self.assertNumQueries(1):
            temp = instance.pgp_sym_field

        self.assertEqual(temp, expected)

    def test_only(self):
        """Test only() functionality."""
        expected = 'bonjour'
        EncryptedModelFactory.create(pgp_sym_field=expected)
        instance = self.model.objects.only('pgp_sym_field').get()

        # Assert that accessing a field in only() does not cause a query
        with self.assertNumQueries(0):
            temp = instance.pgp_sym_field

        self.assertEqual(temp, expected)

    def test_fk_auto_decryption(self):
        """Test auto decryption of FK when select related is defined."""
        expected = 'bonjour'
        EncryptedModelFactory.create(fk_model__fk_pgp_sym_field=expected)
        instance = self.model.objects.select_related('fk_model').get()

        # Assert no additional queries are made to decrypt
        with self.assertNumQueries(0):
            temp = instance.fk_model.fk_pgp_sym_field

        self.assertEqual(temp, expected)

    def test_aggregates(self):
        """Test aggregate support."""
        EncryptedModelFactory.create(datetime_pgp_sym_field=datetime(2016, 7, 1, 0, 0, 0))
        EncryptedModelFactory.create(datetime_pgp_sym_field=datetime(2016, 7, 2, 0, 0, 0))
        EncryptedModelFactory.create(datetime_pgp_sym_field=datetime(2016, 8, 1, 0, 0, 0))
        EncryptedModelFactory.create(datetime_pgp_sym_field=datetime(2016, 9, 1, 0, 0, 0))
        EncryptedModelFactory.create(datetime_pgp_sym_field=datetime(2016, 9, 2, 0, 0, 0))

        total_2016 = self.model.objects.aggregate(
            count=models.Count('datetime_pgp_sym_field')
        )

        self.assertEqual(5, total_2016['count'])

        total_july = self.model.objects.filter(
            datetime_pgp_sym_field__range=[
                datetime(2016, 7, 1, 0, 0, 0),
                datetime(2016, 7, 30, 23, 59, 59)
            ]
        ).aggregate(
            count=models.Count('datetime_pgp_sym_field')
        )

        self.assertEqual(2, total_july['count'])

        total_2016 = self.model.objects.aggregate(
            count=models.Count('datetime_pgp_sym_field'),
            min=models.Min('datetime_pgp_sym_field'),
            max=models.Max('datetime_pgp_sym_field'),
        )

        self.assertEqual(5, total_2016['count'])
        self.assertEqual(datetime(2016, 7, 1, 0, 0, 0), total_2016['min'])
        self.assertEqual(datetime(2016, 9, 2, 0, 0, 0), total_2016['max'])

        total_july = self.model.objects.filter(
            datetime_pgp_sym_field__range=[
                datetime(2016, 7, 1, 0, 0, 0),
                datetime(2016, 7, 30, 23, 59, 59)
            ]
        ).aggregate(
            count=models.Count('datetime_pgp_sym_field'),
            min=models.Min('datetime_pgp_sym_field'),
            max=models.Max('datetime_pgp_sym_field'),
        )

        self.assertEqual(2, total_july['count'])
        self.assertEqual(datetime(2016, 7, 1, 0, 0, 0), total_july['min'])
        self.assertEqual(datetime(2016, 7, 2, 0, 0, 0), total_july['max'])

    def test_distinct(self):
        """Test distinct support."""
        EncryptedModelFactory.create(pgp_sym_field='Paul')
        EncryptedModelFactory.create(pgp_sym_field='Paul')
        EncryptedModelFactory.create(pgp_sym_field='Peter')
        EncryptedModelFactory.create(pgp_sym_field='Peter')
        EncryptedModelFactory.create(pgp_sym_field='Jessica')
        EncryptedModelFactory.create(pgp_sym_field='Jessica')

        items = self.model.objects.filter(
            pgp_sym_field__startswith='P'
        ).annotate(
            _distinct=models.F('pgp_sym_field')
        ).only(
            'id', 'pgp_sym_field', 'fk_model__fk_pgp_sym_field'
        ).distinct(
            '_distinct'
        )

        self.assertEqual(
            2,
            len(items)
        )

        # This only works on Django 2.1+
        if DJANGO_VERSION[0] >= 2 and DJANGO_VERSION[1] >= 1:
            items = self.model.objects.filter(
                pgp_sym_field__startswith='P'
            ).only(
                'id', 'pgp_sym_field', 'fk_model__fk_pgp_sym_field'
            ).distinct(
                'pgp_sym_field'
            )

            self.assertEqual(
                2,
                len(items)
            )

    def test_annotate(self):
        """Test annotate support."""
        efk = EncryptedFKModelFactory.create()
        EncryptedModelFactory.create(pgp_sym_field='Paul', fk_model=efk)
        EncryptedModelFactory.create(pgp_sym_field='Peter', fk_model=efk)
        EncryptedModelFactory.create(pgp_sym_field='Peter', fk_model=efk)
        EncryptedModelFactory.create(pgp_sym_field='Jessica', fk_model=efk)

        items = EncryptedFKModel.objects.annotate(
            name_count=models.Count('encryptedmodel')
        )

        self.assertEqual(
            4,
            items[0].name_count
        )

        items = EncryptedFKModel.objects.filter(
            encryptedmodel__pgp_sym_field__startswith='J'
        ).annotate(
            name_count=models.Count('encryptedmodel')
        )

        self.assertEqual(
            1,
            items[0].name_count
        )

    def test_get_col(self):
        """Test get_col for related alias."""
        related = EncryptedDateTime.objects.create(value=datetime.now())
        related_again = EncryptedDateTime.objects.create(value=datetime.now())

        RelatedDateTime.objects.create(related=related, related_again=related_again)

        instance = RelatedDateTime.objects.select_related(
            'related', 'related_again'
        ).get()

        self.assertIsInstance(instance, RelatedDateTime)

    def test_char_field_choices(self):
        """Test CharField choices."""
        expected = 1
        instance = EncryptedDiff.objects.create(
            sym_field=expected,
        )
        instance.refresh_from_db()

        self.assertTrue(
            '{}'.format(expected),
            instance.sym_field
        )

    def test_write_to_diff_keys(self):
        """Test writing to diff_keys db which uses different keys."""
        expected = 'a'
        instance = EncryptedDiff.objects.create(
            sym_field=expected,
        )

        reset_queries()  # Required for Django 1.11
        instance = EncryptedDiff.objects.get()

        self.assertTrue(
            instance.sym_field,
            expected
        )


