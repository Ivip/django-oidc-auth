from urllib import urlencode
from django.conf import settings
from django.http import HttpResponseBadRequest, HttpResponse, HttpResponseNotAllowed, HttpResponseForbidden,\
    HttpResponseServerError
from django.contrib.auth import REDIRECT_FIELD_NAME, authenticate, login as django_login
from django.core.urlresolvers import reverse
from django.shortcuts import render, redirect
import requests

from . import errors
from . import utils
from .utils import log, import_from_str
from .settings import oidc_settings
from .forms import OpenIDConnectForm
from .models import OpenIDProvider, get_default_provider


def login_begin(request, template_name='oidc/login.html',
        form_class=OpenIDConnectForm,
        login_complete_view='oidc-complete',
        redirect_field_name=REDIRECT_FIELD_NAME):

    if _redirect_to_provider(request):
        issuer = None
        if request.method == 'POST':
            form = form_class(request.POST)
            if form.is_valid():
                issuer = form.cleaned_data['iss']

        return _redirect(request, login_complete_view, issuer, redirect_field_name, None)

    log.debug('Rendering login template at %s' % template_name)
    return render(request, template_name)


def login_initiate(request, 
        login_complete_view='oidc-complete', 
        issuer=None,
        redirect_field_name=REDIRECT_FIELD_NAME,
        login_data=None):

    if oidc_settings.DISABLE_OIDC:
        return HttpResponse("OIDC is disabled", status=503)

    return _redirect(request, login_complete_view, issuer, redirect_field_name, login_data)


def _redirect(request, login_complete_view, issuer, redirect_field_name, login_data):
    if request.method not in ['POST', 'GET']:
        return HttpResponseNotAllowed(['POST', 'GET'])

    if issuer:
        try:
            provider = OpenIDProvider.discover(issuer=issuer)
        except errors.InvalidIssuer:
            provider = None
    else:
        provider = get_default_provider()

    if not provider:
        return HttpResponseBadRequest('Invalid issuer')

    redirect_url = request.GET.get(redirect_field_name, settings.LOGIN_REDIRECT_URL)

    if not request.session.exists(request.session.session_key):
        request.session.create()

    Nonce = import_from_str(oidc_settings.STATE_KEEPER)
    state = None
    try:
        state = Nonce.generate(request, request.session.session_key, redirect_url, provider.issuer, 
            state_data=login_data)
    except errors.DataError:
        return HttpResponseBadRequest("Invalid data passed")
    if state is None:
        return HttpResponseServerError("Cannot create login state")

    redirect_url = oidc_settings.COMPLETE_URL
    if redirect_url is None:
        redirect_url = reverse(login_complete_view)

    params = urlencode({
        'response_type': 'code',
        'scope': utils.scopes(),
        'redirect_uri': request.build_absolute_uri(redirect_url),
        'client_id': provider.client_id,
        'state': state
    })
    redirect_url = '%s?%s' % (provider.authorization_endpoint, params)

    log.debug('Redirecting to %s' % redirect_url)
    return redirect(redirect_url)


def login_complete(request, login_complete_view='oidc-complete',
        error_template_name='oidc/error.html'):

    if 'error' in request.GET:
        return render(request, error_template_name, {
            'error': request.GET['error']
        })

    if 'code' not in request.GET and 'state' not in request.GET:
        return HttpResponseBadRequest('Invalid request')

    state = request.GET['state']

    Nonce = import_from_str(oidc_settings.STATE_KEEPER)
    nonce = Nonce.validate(request, request.session.session_key, state)
    if nonce is None:
        return HttpResponseBadRequest('Invalid state')

    provider = OpenIDProvider.objects.get(issuer=nonce.issuer_url)
    log.debug('Login started from provider %s' % provider)

    redirect_url = oidc_settings.COMPLETE_URL
    if redirect_url is None:
        redirect_url = reverse(login_complete_view)

    params = {
        'grant_type': 'authorization_code',
        'code': request.GET['code'],
        'redirect_uri': request.build_absolute_uri(redirect_url)
    }

    response = requests.post(provider.token_endpoint,
                             auth=provider.client_credentials,
                             data=params, verify=oidc_settings.VERIFY_SSL)

    if response.status_code != 200:
        log.debug('Token request failed %d' % response.status_code)
        return HttpResponseServerError('Token request failed')

    log.debug('Token exchange done, proceeding authentication')
    credentials = response.json()
    credentials['provider'] = provider
    extra = {'session_key': request.session.session_key}
    if nonce.state_data is not None:
        extra['login_data'] = nonce.state_data

    user = None
    try:
        user = authenticate(credentials=credentials, **extra)
    except errors.OpenIDConnectError:
        return HttpResponseServerError('Login processing failed')
    if user is None:
        return HttpResponseForbidden('Invalid user credentials')

    django_login(request, user)

    if oidc_settings.LOGIN_COMPLETE:
        hook = import_from_str(oidc_settings.LOGIN_COMPLETE)
        return hook(request, state, nonce.redirect_url)

    return redirect(nonce.redirect_url)


def _redirect_to_provider(request):
    """Just a syntax sugar for login_begin. Returns True or False
    whether a request should be redirected to the provider or not.
    """

    has_default_provider = oidc_settings.DEFAULT_PROVIDER

    return (not oidc_settings.DISABLE_OIDC
            and (has_default_provider 
                    or request.method == 'POST'))
