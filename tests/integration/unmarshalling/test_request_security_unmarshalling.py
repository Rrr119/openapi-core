import pytest

from openapi_core.testing import MockRequest
from openapi_core.unmarshalling.request.unmarshallers import (
    V30RequestUnmarshaller,
)
from openapi_core.validation.request.exceptions import SecurityValidationError


@pytest.fixture(scope="class")
def schema_path(schema_path_factory):
    return schema_path_factory.from_file("data/v3.0/security_schemes.yaml")


@pytest.fixture(scope="class")
def request_unmarshaller(schema_path):
    return V30RequestUnmarshaller(schema_path)


class TestRequestSecurityUnmarshalling:
    host_url = "http://petstore.swagger.io"

    def test_oauth2_security_result(self, request_unmarshaller):
        request = MockRequest(
            self.host_url,
            "get",
            "/oauth/scoped",
            headers={
                "Authorization": "Bearer access-token",
                "X-Allowed-Scopes": "write:pets read:pets",
            },
        )

        result = request_unmarshaller.unmarshal(request)

        assert not result.errors
        assert result.security == {"oauth2": "access-token"}

    def test_oauth2_missing_scope_error(self, request_unmarshaller):
        request = MockRequest(
            self.host_url,
            "get",
            "/oauth/scoped",
            headers={
                "Authorization": "Bearer access-token",
                "X-Allowed-Scopes": "read:pets",
            },
        )

        result = request_unmarshaller.unmarshal(request)

        assert len(result.errors) == 1
        assert type(result.errors[0]) is SecurityValidationError
        assert result.security is None

    def test_combined_security_result(self, request_unmarshaller):
        request = MockRequest(
            self.host_url,
            "post",
            "/combined",
            args={"api_key": "12345"},
            headers={
                "Authorization": "Bearer access-token",
                "X-Allowed-Scopes": "write:pets",
            },
        )

        result = request_unmarshaller.unmarshal(request)

        assert not result.errors
        assert result.security == {
            "api_key": "12345",
            "oauth2": "access-token",
        }

    def test_empty_security_requirement(self, request_unmarshaller):
        request = MockRequest(self.host_url, "get", "/public")

        result = request_unmarshaller.unmarshal(request)

        assert not result.errors
        assert result.security == {}
