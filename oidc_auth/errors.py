from .utils import log


class OpenIDConnectError(RuntimeError):
    def __init__(self, message=None):
        if not message:
            message = getattr(self, 'message', '')

        log.error(message)
        super(OpenIDConnectError, self).__init__(message)


class InvalidIdToken(OpenIDConnectError, ValueError):
    message = 'id_token MUST be signed'


class TokenValidationError(OpenIDConnectError, ValueError):
    def __init__(self, name):
        message = 'Token validation %s failed' % name
        super(TokenValidationError, self).__init__(message)


class UnsupportedSigningMethod(OpenIDConnectError, ValueError):
    def __init__(self, unsupported_method, supported_methods):
        message = 'Signing method %s not supported, options are (%s)' % (
                unsupported_method, ', '.join(supported_methods))

        super(UnsupportedSigningMethod, self).__init__(message)


class RequestError(OpenIDConnectError):
    def __init__(self, url, status_code):
        message = 'GET %s returned %s status code (200 expected)' % (url, status_code)
        super(RequestError, self).__init__(message)


class InvalidUserInfo(OpenIDConnectError):
    message = 'The received sub does not match the value found in the ID token'


class ForbiddenAuthRequest(OpenIDConnectError):
    message = 'querystring state differs from state saved on session'


class InvalidIssuer(OpenIDConnectError):
    message = "Missing or invalid OIDC provider URL"


class DataError(OpenIDConnectError, ValueError):
    message = "Invalid data passed"
