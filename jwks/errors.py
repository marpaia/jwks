class AuthError(Exception):
    pass


class KeyIDNotFoundError(AuthError):
    pass


class InvalidTokenError(AuthError):
    pass


class InvalidHeaderError(InvalidTokenError):
    pass


class InvalidClaimsError(InvalidTokenError):
    pass


class TokenExpiredError(AuthError):
    pass
