import pytest
from jsonschema_path import SchemaPath

from openapi_core.security.factories import SecurityProviderFactory
from openapi_core.security.providers import ApiKeyProvider
from openapi_core.security.providers import HttpProvider
from openapi_core.security.providers import OAuth2Provider
from openapi_core.security.providers import OpenIdConnectProvider


@pytest.mark.parametrize(
    "scheme_type,provider_cls",
    [
        ("apiKey", ApiKeyProvider),
        ("http", HttpProvider),
        ("oauth2", OAuth2Provider),
        ("openIdConnect", OpenIdConnectProvider),
    ],
)
def test_security_provider_factory(scheme_type, provider_cls):
    scheme = SchemaPath.from_dict({"type": scheme_type})

    provider = SecurityProviderFactory().create(scheme)

    assert isinstance(provider, provider_cls)
