import os

from django.conf import settings
from django.utils import six


def _get_setting(name):
    setting_name = "DEFF_{}".format(name)
    return os.getenv(setting_name, getattr(settings, setting_name, None))


def get_bytes(v):
    if isinstance(v, six.string_types):
        return bytes(v.encode("utf-8"))

    if isinstance(v, bytes):
        return v

    raise TypeError(
        "SALT & PASSWORD must be specified as strings that convert nicely to "
        "bytes."
    )


SALT = get_bytes(_get_setting("SALT"))
FETCH_URL_NAME = _get_setting("FETCH_URL_NAME")
REDIS_HOST = _get_setting("REDIS_HOST")
REDIS_PORT = _get_setting("REDIS_PORT")
