from django.contrib.auth import get_user_model

from .settings import oidc_settings
from .utils import log, import_from_str
from .models import OpenIDProvider
from . import errors

import requests

class OpenIDConnectBackend(object):
    supports_object_permissions = False
    supports_anonymous_user = True

    def _get_user_manager(self):
        if oidc_settings.USER_MANAGER:
            return import_from_str(oidc_settings.USER_MANAGER)
        return None

    def get_user(self, user_id):
        manager = self._get_user_manager()
        if manager:
            return manager.get_user_by_id(user_id)
        return None

    def authenticate(self, **kwargs):
        try:
            credentials = kwargs.get('credentials')
            if not credentials:
                return None

            provider = credentials['provider']
            id_token = provider.verify_id_token(credentials['id_token'])

            if id_token['iss'] != provider.issuer:
                log.error('ISS validation %s != %s', id_token['iss'], provider.issuer)
                raise errors.TokenValidationError('id_token.iss')

            manager = self._get_user_manager()
            if manager:
                access = OpenIDAccess(provider)
                credentials['provider'] = provider.issuer
                credentials['id_token'] = id_token
                return manager.get_user_by_token(credentials, access)
            return None
        except Exception as e:
            log.error('Unexpected %s on authentication: %s', e.__class__.__name__, e)
            raise


class OpenIDAccess(object):
    def __init__(self, provider=None):
        self._provider = provider

    def get_userinfo(self, token):
        id_token = token['id_token']
        access_token = token['access_token']

        if not self._provider or self._provider.issuer != id_token['iss']:
            if self._provider:
                log.error('Wrong saved provider: %s != %s', self._provider.issuer, id_token['iss'])
            self._provider = OpenIDProvider.objects.get(issuer=id_token['iss'])

        sub = id_token['sub']
        log.debug('Requesting userinfo in %s. sub: %s, access_token: %s' % (
            self._provider.userinfo_endpoint, sub, access_token))

        response = requests.get(self._provider.userinfo_endpoint, headers={
            'Authorization': 'Bearer %s' % access_token
        }, verify=oidc_settings.VERIFY_SSL)

        if response.status_code != 200:
            raise errors.RequestError(self._provider.userinfo_endpoint, response.status_code)

        claims = response.json()

        if claims['sub'] != sub:
            raise errors.InvalidUserInfo()

        name = '%s %s' % (claims.get('given_name', ''), claims.get('family_name', ''))
        log.debug('userinfo of sub: %s -> name: %s, preferred_username: %s, email: %s' % (sub,
            name, claims.get('preferred_username', ''), claims.get('email')))

        return claims
