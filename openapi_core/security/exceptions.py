from dataclasses import dataclass
from typing import List

from openapi_core.exceptions import OpenAPIError


class SecurityProviderError(OpenAPIError):
    """Security provider error"""


class SecuritySchemeNotFound(SecurityProviderError):
    """Security scheme not found in components.securitySchemes"""

    def __init__(self, scheme_name: str):
        self.scheme_name = scheme_name

    def __str__(self) -> str:
        return (
            f"Security scheme {self.scheme_name!r} not found in "
            "components.securitySchemes"
        )


@dataclass
class SecurityScopeError(SecurityProviderError):
    """Security scheme scopes do not satisfy the required scopes"""

    scheme_name: str
    required_scopes: List[str]
    granted_scopes: List[str]

    def __str__(self) -> str:
        missing_scopes = [
            scope
            for scope in self.required_scopes
            if scope not in self.granted_scopes
        ]
        return (
            f"Security scheme {self.scheme_name!r} is missing required "
            f"scopes: {', '.join(missing_scopes)}"
        )
