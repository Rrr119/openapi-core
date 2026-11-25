import pytest
from jsonschema_path import SchemaPath

from openapi_core.security.exceptions import SecurityProviderError
from openapi_core.security.providers import ApiKeyProvider
from openapi_core.security.providers import HttpProvider
from openapi_core.testing import MockRequest


class TestHttpProvider:
    @pytest.mark.parametrize(
        "header",
        ["authorization", "Authorization", "AUTHORIZATION"],
    )
    @pytest.mark.parametrize(
        "scheme",
        ["basic", "bearer", "digest"],
    )
    def test_header(self, header, scheme):
        """Tests HttpProvider against Issue29427
        https://bugs.python.org/issue29427
        """
        spec = {
            "type": "http",
            "scheme": scheme,
        }
        value = "MQ"
        headers = {
            header: " ".join([scheme.title(), value]),
        }
        request = MockRequest(
            "http://localhost",
            "GET",
            "/pets",
            headers=headers,
        )
        scheme = SchemaPath.from_dict(spec)
        provider = HttpProvider(scheme)

        result = provider(request.parameters)

        assert result == value

    def test_missing_authorization_header(self):
        scheme = SchemaPath.from_dict({"type": "http", "scheme": "basic"})
        provider = HttpProvider(scheme)
        request = MockRequest("http://localhost", "GET", "/pets")

        with pytest.raises(SecurityProviderError):
            provider(request.parameters)

    def test_malformed_authorization_header(self):
        scheme = SchemaPath.from_dict({"type": "http", "scheme": "basic"})
        provider = HttpProvider(scheme)
        request = MockRequest(
            "http://localhost",
            "GET",
            "/pets",
            headers={"Authorization": "Basic"},
        )

        with pytest.raises(SecurityProviderError):
            provider(request.parameters)

    def test_unknown_authorization_method(self):
        scheme = SchemaPath.from_dict({"type": "http", "scheme": "basic"})
        provider = HttpProvider(scheme)
        request = MockRequest(
            "http://localhost",
            "GET",
            "/pets",
            headers={"Authorization": "Bearer credentials"},
        )

        with pytest.raises(SecurityProviderError):
            provider(request.parameters)


class TestApiKeyProvider:
    def test_valid_query_key(self):
        scheme = SchemaPath.from_dict(
            {"type": "apiKey", "name": "api_key", "in": "query"}
        )
        provider = ApiKeyProvider(scheme)
        request = MockRequest(
            "http://localhost",
            "GET",
            "/pets",
            args={"api_key": "secret"},
        )

        result = provider(request.parameters)

        assert result == "secret"

    def test_missing_query_key(self):
        scheme = SchemaPath.from_dict(
            {"type": "apiKey", "name": "api_key", "in": "query"}
        )
        provider = ApiKeyProvider(scheme)
        request = MockRequest("http://localhost", "GET", "/pets")

        with pytest.raises(SecurityProviderError):
            provider(request.parameters)

    def test_required_scopes_are_ignored(self):
        # apiKey security requirements never list scopes; the argument is
        # accepted for provider interface compatibility.
        scheme = SchemaPath.from_dict(
            {"type": "apiKey", "name": "api_key", "in": "query"}
        )
        provider = ApiKeyProvider(scheme)
        request = MockRequest(
            "http://localhost",
            "GET",
            "/pets",
            args={"api_key": "secret"},
        )

        result = provider(request.parameters, required_scopes=["any"])

        assert result == "secret"
