from base64 import b64encode

import pytest

from openapi_core import V30RequestValidator
from openapi_core.templating.security.exceptions import SecurityNotFound
from openapi_core.testing import MockRequest
from openapi_core.validation.request import V30RequestSecurityValidator
from openapi_core.validation.request.exceptions import SecurityValidationError


@pytest.fixture(scope="class")
def schema_path(schema_path_factory):
    return schema_path_factory.from_file("data/v3.0/security_schemes.yaml")


@pytest.fixture(scope="class")
def request_validator(schema_path):
    return V30RequestValidator(schema_path)


@pytest.fixture(scope="class")
def request_security_validator(schema_path):
    return V30RequestSecurityValidator(schema_path)


class TestRequestSecurity:
    """Security checks for the 10 API request scenarios of
    data/v3.0/security_schemes.yaml (tests 1-10), plus fallback and
    integration edge cases (tests 11-15).
    """

    host_url = "http://petstore.swagger.io"

    api_key = "12345"

    @property
    def api_key_encoded(self):
        api_key_bytes = self.api_key.encode("utf8")
        return str(b64encode(api_key_bytes), "utf8")

    def _validate(self, request_validator, request):
        return request_validator.validate(request)

    # 1. Operation with an empty security requirement is always valid.
    def test_no_security_requirement(self, request_validator):
        request = MockRequest(self.host_url, "get", "/public")

        result = self._validate(request_validator, request)

        assert result is None

    # 2. apiKey requirement satisfied by the configured request parameter.
    def test_api_key_valid(self, request_validator):
        request = MockRequest(
            self.host_url,
            "get",
            "/api-key",
            args={"api_key": self.api_key},
        )

        result = self._validate(request_validator, request)

        assert result is None

    # 3. apiKey requirement fails when the parameter is missing.
    def test_api_key_missing(self, request_validator):
        request = MockRequest(self.host_url, "get", "/api-key")

        with pytest.raises(SecurityValidationError) as exc_info:
            self._validate(request_validator, request)

        assert type(exc_info.value.__cause__) is SecurityNotFound

    # 4. http basic requirement satisfied by a valid Authorization header.
    def test_http_basic_valid(self, request_validator):
        request = MockRequest(
            self.host_url,
            "get",
            "/http-basic",
            headers={"Authorization": "Basic " + self.api_key_encoded},
        )

        result = self._validate(request_validator, request)

        assert result is None

    # 5. http basic requirement fails when the header is absent.
    def test_http_basic_missing_header(self, request_validator):
        request = MockRequest(self.host_url, "get", "/http-basic")

        with pytest.raises(SecurityValidationError) as exc_info:
            self._validate(request_validator, request)

        assert type(exc_info.value.__cause__) is SecurityNotFound

    # 6. http basic requirement fails on an unsupported authorization scheme.
    def test_http_basic_wrong_scheme(self, request_validator):
        request = MockRequest(
            self.host_url,
            "get",
            "/http-basic",
            headers={"Authorization": "Bearer token"},
        )

        with pytest.raises(SecurityValidationError) as exc_info:
            self._validate(request_validator, request)

        assert type(exc_info.value.__cause__) is SecurityNotFound

    # 7. oauth2 requirement satisfied when all required scopes are granted.
    def test_oauth2_valid_scopes(self, request_validator):
        request = MockRequest(
            self.host_url,
            "get",
            "/oauth/scoped",
            headers={
                "Authorization": "Bearer access-token",
                "X-Allowed-Scopes": "write:pets read:pets",
            },
        )

        result = self._validate(request_validator, request)

        assert result is None

    # 8. oauth2 requirement fails when a required scope is not granted.
    def test_oauth2_missing_scope(self, request_validator):
        request = MockRequest(
            self.host_url,
            "get",
            "/oauth/scoped",
            headers={
                "Authorization": "Bearer access-token",
                "X-Allowed-Scopes": "read:pets",
            },
        )

        with pytest.raises(SecurityValidationError) as exc_info:
            self._validate(request_validator, request)

        cause = exc_info.value.__cause__
        assert type(cause) is SecurityNotFound
        assert type(cause.schemes) is list
        assert cause.schemes == [["oauth2"]]

    # 9. oauth2 requirement without scopes only needs a bearer token.
    def test_oauth2_without_required_scopes(self, request_validator):
        request = MockRequest(
            self.host_url,
            "get",
            "/oauth/optional",
            headers={"Authorization": "Bearer access-token"},
        )

        result = self._validate(request_validator, request)

        assert result is None

    # 10. Combined requirement (AND) needs every scheme to be satisfied.
    def test_combined_requirement(self, request_validator):
        valid_request = MockRequest(
            self.host_url,
            "post",
            "/combined",
            args={"api_key": self.api_key},
            headers={
                "Authorization": "Bearer access-token",
                "X-Allowed-Scopes": "write:pets",
            },
        )
        invalid_request = MockRequest(
            self.host_url,
            "post",
            "/combined",
            args={"api_key": self.api_key},
            headers={
                "Authorization": "Bearer access-token",
                "X-Allowed-Scopes": "read:pets",
            },
        )

        assert self._validate(request_validator, valid_request) is None

        with pytest.raises(SecurityValidationError) as exc_info:
            self._validate(request_validator, invalid_request)

        assert type(exc_info.value.__cause__) is SecurityNotFound

    # 11. Root-level security alternatives (OR) accept any satisfied option.
    def test_default_security_alternative_satisfied(self, request_validator):
        request_with_api_key = MockRequest(
            self.host_url,
            "get",
            "/default",
            args={"api_key": self.api_key},
        )

        assert self._validate(request_validator, request_with_api_key) is None

    # 12. Root-level security alternatives fail when none can be satisfied.
    def test_default_security_alternative_missing(self, request_validator):
        request = MockRequest(self.host_url, "get", "/default")

        with pytest.raises(SecurityValidationError) as exc_info:
            self._validate(request_validator, request)

        cause = exc_info.value.__cause__
        assert type(cause) is SecurityNotFound
        assert cause.schemes == [["api_key"], ["oauth2"]]

    # 13. Undefined security schemes are reported as validation errors.
    def test_undefined_security_scheme(self, request_validator):
        request = MockRequest(self.host_url, "get", "/undefined")

        with pytest.raises(SecurityValidationError) as exc_info:
            self._validate(request_validator, request)

        cause = exc_info.value.__cause__
        assert type(cause) is SecurityNotFound
        assert cause.schemes == [["undefined_scheme"]]

    # 14. Security validation short-circuits parameter and body validation.
    def test_security_error_short_circuits(self, request_validator):
        request = MockRequest(self.host_url, "get", "/oauth/scoped")

        with pytest.raises(SecurityValidationError):
            self._validate(request_validator, request)

    # 15. The dedicated security-only validator reports the same errors.
    def test_dedicated_security_validator(self, request_security_validator):
        valid_request = MockRequest(
            self.host_url,
            "get",
            "/oauth/scoped",
            headers={
                "Authorization": "Bearer access-token",
                "X-Allowed-Scopes": "write:pets read:pets",
            },
        )
        invalid_request = MockRequest(
            self.host_url,
            "get",
            "/oauth/scoped",
            headers={"Authorization": "Bearer access-token"},
        )

        assert (
            list(request_security_validator.iter_errors(valid_request)) == []
        )
        errors = list(request_security_validator.iter_errors(invalid_request))
        assert len(errors) == 1
        assert type(errors[0]) is SecurityValidationError
        assert type(errors[0].__cause__) is SecurityNotFound
