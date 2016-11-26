from .utils import log


class OpenIDConnectError(RuntimeError):
    code = 500
    def __init__(self, message=None):
        if not message:
            message = getattr(self, 'message', '')

        log.error(message)
        super(OpenIDConnectError, self).__init__(message)


class InvalidIdToken(OpenIDConnectError, ValueError):
    code = 401
    message = 'id_token MUST be signed'


class TokenValidationError(OpenIDConnectError, ValueError):
    code = 401
    def __init__(self, name):
        message = 'Token validation %s failed' % name
        super(TokenValidationError, self).__init__(message)


class UnsupportedSigningMethod(OpenIDConnectError, ValueError):
    code = 500
    def __init__(self, unsupported_method, supported_methods):
        message = 'Signing method %s not supported, options are (%s)' % (
                unsupported_method, ', '.join(supported_methods))

        super(UnsupportedSigningMethod, self).__init__(message)


class RequestError(OpenIDConnectError):
    code = 500
    def __init__(self, url, status_code):
        message = 'GET %s returned %s status code (200 expected)' % (url, status_code)
        super(RequestError, self).__init__(message)


class InvalidUserInfo(OpenIDConnectError):
    code = 401
    message = 'The received sub does not match the value found in the ID token'


class ForbiddenAuthRequest(OpenIDConnectError):
    code = 401
    message = 'querystring state differs from state saved on session'


class InvalidIssuer(OpenIDConnectError):
    code = 400
    message = "Missing or invalid OIDC provider URL"


class DataError(OpenIDConnectError, ValueError):
    code = 400
    message = "Invalid data passed"
