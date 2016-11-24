import string
import random
from urlparse import urljoin
import requests
from django.db import models, IntegrityError
from django.core.exceptions import ValidationError
from jwkest.jwk import load_jwks_from_url
from jwkest.jws import JWS
from jwkest.jwk import SYMKey

from . import errors
from .settings import oidc_settings
from .utils import log, b64decode


class Nonce(models.Model):
    issuer_url = models.URLField()
    state = models.CharField(max_length=255, unique=True)
    redirect_url = models.CharField(max_length=100)
    session_id = models.CharField(max_length=128)
    created = models.DateTimeField(auto_now_add=True)
    state_data = models.CharField(max_length=255, null=True, blank=True)

    def __unicode__(self):
        return '%s' % self.state

    def __init__(self, *args, **kwargs):
        super(Nonce, self).__init__(*args, **kwargs)

    @staticmethod
    def nonce(length=oidc_settings.NONCE_LENGTH):
        """Generate nonce string"""
        CHARS = string.letters + string.digits
        return ''.join(random.choice(CHARS) for n in range(length))

    @classmethod
    def generate(cls, request, session_id, redirect_url, issuer_url, nonce=None, state_data=None):
        """Generate and return state string for specified session"""
        state = nonce or cls.nonce()
        try:
            obj = cls(issuer_url=issuer_url, state=state,
                    session_id=session_id, redirect_url=redirect_url, state_data=state_data)
            """Validate size constraints because DB may silently trim values"""
            obj.clean_fields()
            obj.save(force_insert=True)
            return state
        except ValidationError as e:
            raise errors.DataError(str(e))
        except IntegrityError:
            return None

    @classmethod
    def validate(cls, request, session_id, state):
        """This method validates nonce for the session and returns
            object with redirect_url and issuer or None"""
        try:
            return cls.objects.get(state=state, session_id=session_id)
        except cls.DoesNotExist:
            return None


class OpenIDProvider(models.Model):
    RS256 = 'RS256'
    HS256 = 'HS256'
    SIGNING_ALGS = (
        (RS256, 'RS256'),
        (HS256, 'HS256'),
    )

    issuer = models.URLField(unique=True)
    authorization_endpoint = models.URLField()
    token_endpoint = models.URLField()
    userinfo_endpoint = models.URLField()
    jwks_uri = models.URLField(null=True, blank=True)
    signing_alg = models.CharField(max_length=5, choices=SIGNING_ALGS, default=HS256)

    client_id = models.CharField(max_length=255)
    client_secret = models.CharField(max_length=255)

    def __unicode__(self):
        return self.issuer

    @classmethod
    def discover(cls, issuer='', credentials={}, save=True):
        """Returns a known OIDC Endpoint. If it doesn't exist in the database,
        then it'll fetch its data according to OpenID Connect Discovery spec.
        """
        if not (issuer or credentials):
            raise ValueError('You should provide either an issuer or credentials')

        if not issuer:
            issuer = cls._get_issuer(credentials['id_token'])

        try:
            provider = cls.objects.get(issuer=issuer)
            log.debug('Provider %s already discovered' % issuer)
            return provider
        except cls.DoesNotExist:
            pass

        if oidc_settings.DISABLE_OIDC_DISCOVER:
            raise errors.InvalidIssuer()

        log.debug('Provider %s not discovered yet, proceeding discovery' % issuer)
        discover_endpoint = urljoin(issuer, '.well-known/openid-configuration')
        response = requests.get(discover_endpoint, verify=oidc_settings.VERIFY_SSL)

        if response.status_code != 200:
            raise errors.RequestError(discover_endpoint, response.status_code)

        configs = response.json()
        provider = cls()

        provider.issuer = configs['issuer']
        provider.authorization_endpoint = configs['authorization_endpoint']
        provider.token_endpoint = configs['token_endpoint']
        provider.userinfo_endpoint = configs['userinfo_endpoint']
        provider.jwks_uri = configs['jwks_uri']

        if save:
            provider.save()

        log.debug('Provider %s succesfully discovered' % issuer)
        return provider

    @property
    def client_credentials(self):
        return self.client_id, self.client_secret

    @property
    def signing_keys(self):
        if self.signing_alg == self.RS256:
            # TODO perform caching, OBVIOUS
            return load_jwks_from_url(self.jwks_uri)

        return [SYMKey(key=str(self.client_secret))]

    def verify_id_token(self, token):
        log.debug('Verifying token %s' % token)
        header, claims, signature = token.split('.')
        header = b64decode(header)
        claims = b64decode(claims)

        if not signature:
            raise errors.InvalidIdToken()

        if header['alg'] not in ['HS256', 'RS256']:
            raise errors.UnsupportedSigningMethod(header['alg'], ['HS256', 'RS256'])

        id_token = JWS().verify_compact(token, self.signing_keys)
        log.debug('Token verified, %s' % id_token)
        return id_token

    @staticmethod
    def _get_issuer(token):
        """Parses an id_token and returns its issuer.

        An id_token is a string containing 3 b64-encrypted hashes,
        joined by a dot, like:

            <header>.<claims>.<signature>

        We only need to parse the claims, which contains the 'iss' field
        we're looking for.
        """
        _, claims, _ = token.split('.')

        return b64decode(claims)['iss']


def get_default_provider():
    args = oidc_settings.DEFAULT_PROVIDER

    if not args:
        return

    issuer = args.get('issuer')
    provider, created = OpenIDProvider.objects.get_or_create(issuer=issuer, defaults=args)

    if created:
        return provider

    # Test if the object is up-to-date
    should_update = False
    fields = ['authorization_endpoint', 'token_endpoint',
              'userinfo_endpoint', 'client_id', 'client_secret']

    for field in fields:
        if field in args and getattr(provider, field) != args[field]:
            should_update = True
            setattr(provider, field, args[field])

    if should_update:
        provider.save()

    return provider
