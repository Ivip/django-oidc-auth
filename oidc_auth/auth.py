from urllib import urlencode
import requests

from django.contrib.auth import authenticate, login
from django.core.exceptions import PermissionDenied

from .errors import *
from .settings import oidc_settings
from . import utils
from .utils import log, import_from_str
from .models import OpenIDProvider, get_default_provider


"""
Django Authentication backend
"""
class OpenIDConnectBackend(object):

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
            provider = kwargs.get('provider')
            if not credentials or not provider:
                return None

            id_token = provider.verify_id_token(credentials['id_token'])
            if id_token['iss'] != provider.issuer:
                log.error('ISS validation %s != %s', id_token['iss'], provider.issuer)
                raise TokenValidationError('id_token.iss')

            manager = self._get_user_manager()
            if manager:
                credentials['id_token'] = id_token
                return manager.get_user_by_token(token=credentials, provider=provider, 
                                                    login_data=kwargs.get('login_data'))
            else:
                raise PermissionDenied
        except (InvalidIdToken, TokenValidationError, UnsupportedSigningMethod, PermissionDenied):
            raise
        except Exception as e:
            log.error('Unexpected %s on authentication: %s', e.__class__.__name__, e)
            raise


"""
OIDC Auth
"""
class OpenIDConnectAuth(object):

    def __init__(self, request):
        self.login_data = None
        self.provider = None

        if request.method not in ['POST', 'GET']:
            raise DataError("Invalid method, expect ['POST', 'GET']")
        if not request.session.exists(request.session.session_key):
            request.session.create()
        self.request = request


    @staticmethod
    def get_userinfo(token, provider):
        id_token = token['id_token']
        access_token = token['access_token']

        if not provider or provider.issuer != id_token['iss']:
            if provider:
                log.error('Wrong provider: %s != %s', provider.issuer, id_token['iss'])
            provider = OpenIDProvider.find(issuer=id_token['iss'])

        sub = id_token['sub']
        log.debug('Requesting userinfo from %s, cli: %s, sub: %s' % (
            provider.userinfo_endpoint, provider.client_id, sub))

        response = requests.get(provider.userinfo_endpoint, headers={
            'Authorization': 'Bearer %s' % access_token
        }, verify=oidc_settings.VERIFY_SSL)

        if response.status_code != 200:
            raise RequestError(provider.userinfo_endpoint, response.status_code)

        claims = response.json()

        if claims['sub'] != sub:
            raise InvalidUserInfo()

        return claims

    @staticmethod
    def get_provider(**kwargs):
        if not kwargs:
            return get_default_provider()
        return OpenIDProvider.find(**kwargs)

    """
    Login initialization funtion.
    Retunrs URL pointing to OIDC provider
    """
    def login_init(self, provider, login_data, scopes, complete_url):
        if oidc_settings.DISABLE_OIDC:
            raise OpenIDConnectError("OIDC is disabled")

        if provider is None:
            raise InvalidIssuer()

        Nonce = import_from_str(oidc_settings.STATE_KEEPER)
        state = Nonce.generate(request=self.request, session_id=self.request.session.session_key, 
                                redirect_url=complete_url, provider_id=provider.id, state_data=login_data)
        if state is None:
            raise OpenIDConnectError("Cannot create login state")

        params = urlencode({
            'response_type': 'code',
            'scope': utils.scopes(scopes),
            'redirect_uri': self.request.build_absolute_uri(complete_url),
            'client_id': provider.client_id,
            'state': state
        })
        redirect_url = '%s?%s' % (provider.authorization_endpoint, params)

        log.debug('Redirecting to %s' % redirect_url)
        return redirect_url

    """
    Login completion function
    Returns user credentials
    """
    def login_complete(self):

        if 'error' in self.request.GET:
            raise ForbiddenAuthRequest(self.request.GET['error'])

        if 'code' not in self.request.GET or 'state' not in self.request.GET:
            raise ForbiddenAuthRequest()

        state = self.request.GET['state']

        Nonce = import_from_str(oidc_settings.STATE_KEEPER)
        nonce = Nonce.validate(self.request, self.request.session.session_key, state)
        if nonce is None:
            raise ForbiddenAuthRequest()
        try:
            nonce.delete()
        except:
            log.error("Failed to delete used nonce %s", state)

        self.login_data = nonce.state_data
        self.provider = OpenIDProvider.find(id=nonce.provider_id)
        log.debug('Login started from provider %d' % self.provider.id)

        params = {
            'grant_type': 'authorization_code',
            'code': self.request.GET['code'],
            'redirect_uri': self.request.build_absolute_uri(nonce.redirect_url)
        }

        response = requests.post(self.provider.token_endpoint,
                             auth=self.provider.client_credentials,
                             data=params, verify=oidc_settings.VERIFY_SSL)

        if response.status_code != 200:
            log.debug('Token request failed %d' % response.status_code)
            raise RequestError(self.provider.token_endpoint, response.status_code)

        log.debug('Token exchange done, proceeding authentication')
        credentials = response.json()

        return credentials

    """
    Performs Django authentication and login with passed credentials
    Returns user
    """
    def user_login(self, credentials, login_data=None):
        user = authenticate(credentials=credentials, provider=self.provider, login_data=login_data)
        if user is None:
            return None

        if user.is_authenticated():
            login(self.request, user)

        return user
