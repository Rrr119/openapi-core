from openapi_core.security.exceptions import SecurityProviderError
from openapi_core.security.exceptions import SecuritySchemeNotFound
from openapi_core.security.exceptions import SecurityScopeError


def test_security_scope_error_is_provider_error():
    error = SecurityScopeError(
        scheme_name="oauth2",
        required_scopes=["write:pets"],
        granted_scopes=["read:pets"],
    )

    assert isinstance(error, SecurityProviderError)
    assert str(error) == (
        "Security scheme 'oauth2' is missing required scopes: write:pets"
    )


def test_security_scheme_not_found():
    error = SecuritySchemeNotFound("unknown")

    assert isinstance(error, SecurityProviderError)
    assert error.scheme_name == "unknown"
    assert "unknown" in str(error)
