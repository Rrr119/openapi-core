import pytest
from jsonschema_path import SchemaPath

from openapi_core.security.exceptions import SecurityProviderError
from openapi_core.security.exceptions import SecurityScopeError
from openapi_core.security.providers import OAuth2Provider
from openapi_core.security.providers import OpenIdConnectProvider
from openapi_core.testing import MockRequest


def make_scheme():
    spec = {
        "components": {
            "securitySchemes": {
                "oauth2": {
                    "type": "oauth2",
                    "flows": {
                        "implicit": {
                            "authorizationUrl": (
                                "https://example.com/oauth/authorize"
                            ),
                            "scopes": {
                                "write:pets": "modify pets",
                                "read:pets": "read pets",
                            },
                        },
                    },
                },
            },
        },
    }
    schema_path = SchemaPath.from_dict(spec)
    return schema_path / "components#securitySchemes#oauth2"


class TestOAuth2Provider:
    def test_valid_token_without_required_scopes(self):
        provider = OAuth2Provider(make_scheme())
        request = MockRequest(
            "http://localhost",
            "get",
            "/pets",
            headers={"Authorization": "Bearer access-token"},
        )

        result = provider(request.parameters)

        assert result == "access-token"

    def test_valid_token_with_granted_scopes(self):
        provider = OAuth2Provider(make_scheme())
        request = MockRequest(
            "http://localhost",
            "get",
            "/pets",
            headers={
                "Authorization": "Bearer access-token",
                "X-Allowed-Scopes": "read:pets write:pets",
            },
        )

        result = provider(request.parameters, ["write:pets", "read:pets"])

        assert result == "access-token"

    def test_missing_authorization_header(self):
        provider = OAuth2Provider(make_scheme())
        request = MockRequest("http://localhost", "get", "/pets")

        with pytest.raises(SecurityProviderError):
            provider(request.parameters)

    def test_malformed_authorization_header(self):
        provider = OAuth2Provider(make_scheme())
        request = MockRequest(
            "http://localhost",
            "get",
            "/pets",
            headers={"Authorization": "Bearer"},
        )

        with pytest.raises(SecurityProviderError):
            provider(request.parameters)

    def test_unsupported_authorization_method(self):
        provider = OAuth2Provider(make_scheme())
        request = MockRequest(
            "http://localhost",
            "get",
            "/pets",
            headers={"Authorization": "Basic credentials"},
        )

        with pytest.raises(SecurityProviderError):
            provider(request.parameters)

    def test_missing_required_scope(self):
        provider = OAuth2Provider(make_scheme())
        request = MockRequest(
            "http://localhost",
            "get",
            "/pets",
            headers={
                "Authorization": "Bearer access-token",
                "X-Allowed-Scopes": "read:pets",
            },
        )

        with pytest.raises(SecurityScopeError) as exc_info:
            provider(request.parameters, ["write:pets", "read:pets"])

        error = exc_info.value
        assert error.scheme_name == "oauth2"
        assert error.required_scopes == ["write:pets", "read:pets"]
        assert error.granted_scopes == ["read:pets"]
        assert "write:pets" in str(error)

    def test_no_granted_scopes_header(self):
        provider = OAuth2Provider(make_scheme())
        request = MockRequest(
            "http://localhost",
            "get",
            "/pets",
            headers={"Authorization": "Bearer access-token"},
        )

        with pytest.raises(SecurityScopeError) as exc_info:
            provider(request.parameters, ["read:pets"])

        assert exc_info.value.granted_scopes == []


class TestOpenIdConnectProvider:
    def test_inherits_oauth2_behavior(self):
        spec = {
            "type": "openIdConnect",
            "openIdConnectUrl": (
                "https://example.com/.well-known/openid-configuration"
            ),
        }
        provider = OpenIdConnectProvider(SchemaPath.from_dict(spec))
        request = MockRequest(
            "http://localhost",
            "get",
            "/pets",
            headers={"Authorization": "Bearer access-token"},
        )

        result = provider(request.parameters)

        assert result == "access-token"
