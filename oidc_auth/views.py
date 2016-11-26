from django.conf import settings
from django.http import HttpResponseBadRequest, HttpResponseNotAllowed, HttpResponseForbidden,\
    HttpResponseServerError
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.urlresolvers import reverse
from django.shortcuts import render, redirect

from .errors import *
from .utils import log
from .settings import oidc_settings
from .forms import OpenIDConnectForm
from .models import OpenIDProvider, get_default_provider
from .auth import OpenIDConnectAuth


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

        return _redirect(request, login_complete_view, issuer, redirect_field_name)

    log.debug('Rendering login template at %s' % template_name)
    return render(request, template_name)


def _redirect(request, login_complete_view, issuer, redirect_field_name):
    if request.method not in ['POST', 'GET']:
        return HttpResponseNotAllowed(['POST', 'GET'])

    auth = OpenIDConnectAuth(request)

    if not issuer:
        provider = get_default_provider()
    else:
        try:
            provider = OpenIDProvider.discover(issuer=issuer)
        except InvalidIssuer:
            provider = None
    if not provider:
        return HttpResponseBadRequest('Invalid issuer')

    login_data = request.GET.get(redirect_field_name, settings.LOGIN_REDIRECT_URL)

    complete_url = oidc_settings.COMPLETE_URL
    if complete_url is None:
        complete_url = reverse(login_complete_view)

    redirect_url = auth.login_init(provider, login_data, oidc_settings.SCOPES, complete_url)

    log.debug('Redirecting to %s' % redirect_url)
    return redirect(redirect_url)


def login_complete(request, login_complete_view='oidc-complete',
        error_template_name='oidc/error.html'):

    if 'error' in request.GET:
        return render(request, error_template_name, {
            'error': request.GET['error']
        })

    try:
        auth = OpenIDConnectAuth(request)
        user = auth.user_login(auth.login_complete())
    except (ForbiddenAuthRequest, InvalidUserInfo, TokenValidationError) as e:
        return HttpResponseForbidden(e.message)
    except OpenIDConnectError as e:
        return HttpResponseServerError(e.message)

    if user is None:
        return HttpResponseForbidden('Invalid user credentials')

    return redirect(auth.login_data)


def _redirect_to_provider(request):
    """Just a syntax sugar for login_begin. Returns True or False
    whether a request should be redirected to the provider or not.
    """

    has_default_provider = oidc_settings.DEFAULT_PROVIDER

    return (not oidc_settings.DISABLE_OIDC
            and (has_default_provider 
                    or request.method == 'POST'))
