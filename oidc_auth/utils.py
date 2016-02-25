import json
from base64 import b64decode as python_b64decode
import logging
import importlib

from .settings import oidc_settings


def scopes():
    _scopes = set(oidc_settings.SCOPES)
    _scopes.update({'openid', 'email', 'preferred_username'})

    return ' '.join(_scopes)


def b64decode(token):
    token += ('=' * (len(token) % 4))
    decoded = python_b64decode(token)
    return json.loads(decoded)


def import_from_str(value):
    """
    Attempt to import a class from a string representation.
    This function copied from OIDC Provider project (django-oidc-provider)
    """
    try:
        parts = value.split('.')
        module_path, class_name = '.'.join(parts[:-1]), parts[-1]
        module = importlib.import_module(module_path, package=__name__.rsplit('.', 1)[0])
        return getattr(module, class_name)
    except ImportError as e:
        msg = 'Could not import %s from %s for settings. %s: %s.' % (value, __name__, e.__class__.__name__, e)
        raise ImportError(msg)


log = logging.getLogger('oidc_auth')
log.addHandler(logging.NullHandler())
