import json
import time
from typing import Any, Dict, List
from urllib.parse import urljoin

from jose import jwt
from pydantic import BaseModel
import requests

from .errors import (
    AuthError,
    KeyIDNotFoundError,
    InvalidClaimsError,
    InvalidTokenError,
    InvalidHeaderError,
    TokenExpiredError,
)
from .singleton import Singleton


DEFAULT_ALGORITHMS = ["RS256"]
DEFAULT_GRANT_TYPE = "client_credentials"
DEFAULT_TOKEN_ENDPOINT = "oauth/token"


class JSONWebKey(BaseModel):
    alg: str
    kty: str
    use: str
    n: str
    e: str
    kid: str
    x5t: str
    x5c: List[str]

    def rsa_key(self) -> Dict[str, str]:
        return {
            "kty": self.kty,
            "kid": self.kid,
            "use": self.use,
            "n": self.n,
            "e": self.e,
        }


class JSONWebKeySet(BaseModel):
    keys: List[JSONWebKey]


class TokenFetcher:
    client_id: str
    client_secret: str
    audience: str
    issuer: str
    grant_type: str
    token_endpoint: str

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        audience: str,
        issuer: str,
        grant_type: str = DEFAULT_GRANT_TYPE,
        token_endpoint: str = DEFAULT_TOKEN_ENDPOINT,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.audience = audience
        self.issuer = issuer
        self.grant_type = grant_type
        self.token_endpoint = token_endpoint

    def fetch_token(self) -> str:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "audience": self.audience,
            "grant_type": self.grant_type,
        }
        resp = requests.post(
            urljoin(self.issuer, self.token_endpoint),
            headers={"Content-Type": "application/json"},
            data=json.dumps(data),
        )
        if resp.status_code != 200:
            raise AuthError(f"Received HTTP {resp.status_code} from API when fetching token")
        token = resp.json()
        return token["access_token"]


class TokenValidator(Singleton):
    jwks_uri: str
    audience: str
    issuer: str
    algorithms: List[str]

    public_keys: Dict[str, JSONWebKey]
    public_keys_last_refreshed: float
    key_refresh_interval: int

    def __init__(
        self,
        *,
        jwks_uri: str,
        audience: str,
        issuer: str,
        algorithms: List[str] = DEFAULT_ALGORITHMS,
        key_refresh_interval=3600,
    ):
        Singleton.__init__(self)
        self.jwks_uri = jwks_uri
        self.audience = audience
        self.issuer = issuer
        self.algorithms = algorithms
        self.public_keys = {}
        self.key_refresh_interval = key_refresh_interval
        self.refresh_keys()

    def keys_need_refresh(self) -> bool:
        return (time.time() - self.public_keys_last_refreshed) > self.key_refresh_interval

    def refresh_keys(self) -> None:
        resp = requests.get(self.jwks_uri)
        jwks = JSONWebKeySet.parse_raw(resp.text)
        self.public_keys_last_refreshed = time.time()
        self.public_keys.clear()
        for key in jwks.keys:
            self.public_keys[key.kid] = key

    def validate_token(self, token: str, *, num_retries: int = 0) -> Dict[str, Any]:
        # Before we do anything, the validation keys may need to be refreshed.
        # If so, refresh them.
        if self.keys_need_refresh():
            self.refresh_keys()

        # Try to extract the claims from the token so that we can use the key ID
        # to determine which key we should use to validate the token.
        try:
            unverified_claims = jwt.get_unverified_header(token)
        except Exception:
            raise InvalidTokenError("Unable to parse key ID from token")

        # See if we have the key identified by this key ID.
        try:
            key = self.public_keys[unverified_claims["kid"]]
        except KeyError:
            # If we don't have this key and this is the first attempt (ie: we
            # haven't refreshed keys yet), then try to refresh the keys and try
            # again.
            if num_retries == 0:
                self.refresh_keys()
                return self.validate_token(token, num_retries=1)
            else:
                raise KeyIDNotFoundError

        # Now that we have found the key identified by the supplied token's key
        # ID, we try to use it to decode and validate the supplied token.
        try:
            payload = jwt.decode(
                token,
                key.rsa_key(),
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
            )

        # A series of errors may be thrown if the token is invalid. Here, we
        # catch several of them and attempt to return a relatively specific
        # exception. All of these exceptions subclass AuthError so that the
        # caller can just catch AuthError if they want.
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError("Token is expired")
        except jwt.JWTClaimsError:
            raise InvalidClaimsError("Check the audience and issuer")
        except Exception:
            raise InvalidHeaderError("Unable to parse authentication token")

        return payload
