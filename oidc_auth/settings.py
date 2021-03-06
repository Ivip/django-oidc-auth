from contextlib import contextmanager
from django.conf import settings


DEFAULTS = {
    'DISABLE_OIDC': False,
    'DISABLE_OIDC_DISCOVER': False,
    'DEFAULT_PROVIDER': {},
    'SCOPES': (),
    'CLIENT_ID': None,
    'CLIENT_SECRET': None,
    'NONCE_LENGTH': 28,
    'VERIFY_SSL': True,
    'COMPLETE_URL': None,
    'USER_MANAGER': None,
    'STATE_KEEPER': '.models.Nonce',
}

USER_SETTINGS = getattr(settings, 'OIDC_AUTH', {})


class OIDCSettings(object):
    """Shamelessly copied from django-oauth-toolkit"""

    def __init__(self, user_settings, defaults):
        self.user_settings = user_settings
        self.defaults = defaults
        self.patched_settings = {}

    def __getattr__(self, attr):
        if attr not in self.defaults:
            raise AttributeError('Invalid oidc_auth setting: %s' % attr)

        if attr in self.patched_settings:
            val = self.patched_settings[attr]
        elif attr in self.user_settings:
            val = self.user_settings[attr]
        else:
            val = self.defaults[attr]

        return val

    @contextmanager
    def override(self, **kwargs):
        self.patched_settings = kwargs
        yield
        self.patched_settings = {}

oidc_settings = OIDCSettings(USER_SETTINGS, DEFAULTS)
