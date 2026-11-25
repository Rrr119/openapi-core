import warnings
from typing import Any
from typing import List
from typing import Optional
from typing import Sequence

from jsonschema_path import SchemaPath

from openapi_core.datatypes import RequestParameters
from openapi_core.security.exceptions import SecurityProviderError
from openapi_core.security.exceptions import SecurityScopeError

# Header carrying the scopes granted to the request by the authentication
# layer (space-separated, as defined by RFC 6749 section 3.3).
SCOPES_HEADER = "X-Allowed-Scopes"


class BaseProvider:
    def __init__(self, scheme: SchemaPath):
        self.scheme = scheme

    def __call__(
        self,
        parameters: RequestParameters,
        required_scopes: Optional[Sequence[str]] = None,
    ) -> Any:
        raise NotImplementedError


class UnsupportedProvider(BaseProvider):
    def __call__(
        self,
        parameters: RequestParameters,
        required_scopes: Optional[Sequence[str]] = None,
    ) -> Any:
        warnings.warn("Unsupported scheme type")


class ApiKeyProvider(BaseProvider):
    def __call__(
        self,
        parameters: RequestParameters,
        required_scopes: Optional[Sequence[str]] = None,
    ) -> Any:
        name = (self.scheme / "name").read_str()
        location = (self.scheme / "in").read_str()
        source = getattr(parameters, location)
        if name not in source:
            raise SecurityProviderError("Missing api key parameter.")
        return source[name]


class HttpProvider(BaseProvider):
    def __call__(
        self,
        parameters: RequestParameters,
        required_scopes: Optional[Sequence[str]] = None,
    ) -> Any:
        if "Authorization" not in parameters.header:
            raise SecurityProviderError("Missing authorization header.")
        auth_header = parameters.header["Authorization"]
        try:
            auth_type, encoded_credentials = auth_header.split(" ", 1)
        except ValueError:
            raise SecurityProviderError(
                "Could not parse authorization header."
            )

        scheme = self.scheme["scheme"]
        if auth_type.lower() != scheme:
            raise SecurityProviderError(
                f"Unknown authorization method {auth_type}"
            )

        return encoded_credentials


class OAuth2Provider(BaseProvider):
    scopes_header = SCOPES_HEADER

    def __call__(
        self,
        parameters: RequestParameters,
        required_scopes: Optional[Sequence[str]] = None,
    ) -> Any:
        if "Authorization" not in parameters.header:
            raise SecurityProviderError("Missing authorization header.")
        auth_header = parameters.header["Authorization"]
        try:
            auth_type, access_token = auth_header.split(" ", 1)
        except ValueError:
            raise SecurityProviderError(
                "Could not parse authorization header."
            )

        if auth_type.lower() != "bearer":
            raise SecurityProviderError(
                f"Unknown authorization method {auth_type}"
            )

        required = list(required_scopes or [])
        granted = self._get_granted_scopes(parameters)
        missing_scopes = [scope for scope in required if scope not in granted]
        if missing_scopes:
            scheme_name = self._get_scheme_name()
            raise SecurityScopeError(scheme_name, required, granted)

        return access_token

    def _get_scheme_name(self) -> str:
        return self.scheme.name

    def _get_granted_scopes(self, parameters: RequestParameters) -> List[str]:
        header = parameters.header.get(self.scopes_header, "")
        return header.split()


class OpenIdConnectProvider(OAuth2Provider):
    pass
