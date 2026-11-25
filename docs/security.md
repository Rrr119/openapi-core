---
hide:
  - navigation
---

# Security

Openapi-core provides easy access to security data for authentication and authorization processes.

Supported security schemes:

- http – for Basic and Bearer HTTP authentication schemes
- apiKey – for API keys and cookie authentication
- oauth2 – for OAuth2 authentication with scope checking
- openIdConnect – for OpenID Connect authentication (same behavior as oauth2)

Here's an example with `BasicAuth` and `ApiKeyAuth` security schemes:

```yaml
security:
 - BasicAuth: []
 - ApiKeyAuth: []
components:
 securitySchemes:
   BasicAuth:
     type: http
     scheme: basic
   ApiKeyAuth:
     type: apiKey
     in: header
     name: X-API-Key
```

Security scheme data is accessible from the `security` attribute of the `RequestUnmarshalResult` object.

```python
# Get basic auth decoded credentials
result.security['BasicAuth']

# Get API key
result.security['ApiKeyAuth']
```

## OAuth2 scopes

Scopes required by a security requirement object are checked against the
scopes granted to the request. The `OAuth2Provider` reads the bearer token
from the `Authorization` header and the granted scopes from the
`X-Allowed-Scopes` request header (space-separated).

```yaml
security:
  - oauth2:
      - write:pets
      - read:pets
```

When any of the required scopes is missing the security requirement is not
satisfied and, as with other authentication failures, the validator keeps
trying the remaining security requirements. If none of them can be
satisfied a `SecurityValidationError` (caused by `SecurityNotFound`) is
raised.

The scope lookup can be customized by subclassing `OAuth2Provider` and
overriding `_get_granted_scopes`, then registering the provider through a
custom `SecurityProviderFactory` and a `Config` with
`security_provider_factory`.
