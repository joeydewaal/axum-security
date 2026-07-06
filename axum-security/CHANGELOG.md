# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.2](https://github.com/joeydewaal/axum-security/compare/axum-security-v0.0.1...axum-security-v0.0.2) - 2026-07-06

### Added

- *(oidc)* OidcClientBuilder min_refetch_interval + http_client
- *(oidc)* lazy JWKS fetch for the manual builder path

### Fixed

- rustfmt and rustdoc intra-doc links
- *(oauth2)* require explicit cookie secret, surface provider errors, expose refresh
- *(rbac)* restore session into extensions after reading roles in macros
- fix build issues

### Other

- chore
- *(oidc)* migrate axum-security onto axum-security-oidc; drop openidconnect
- Replace auth_type(AuthType) with basic_auth()/request_body()
- Take LoginOptions by value instead of a closure
- Merge remote-tracking branch 'origin/main' into feat/oauth2-phase3
- Use CsrfToken's constant-time PartialEq for the state check; cookie-monster 0.2.2
- Harden the OAuth2 state cookie and CSRF comparison
- Simplify OAuth2ContextBuilder onto the client builder's setters
- Migrate the oauth2 feature onto axum-security-oauth2 (phase 2)
- Merge pull request #12 from joeydewaal/design/oauth2
- wip
- wip
- wip
- format
- remove csrf feature
- some more cleaning
- remove rate-limit
- upgrade deps ([#5](https://github.com/joeydewaal/axum-security/pull/5))
- wip
- wip
- wip
- wip
- wip
- wip
- cleanup
- wip
- wip
- wip
- wip
- wip
- wip
- wip
- wip
- wip
- wip
- wip
- wip
- wip
- wip
- wip
- Reduce allocation
- wip
- wip
- wip
- wip
- wip
- wip
- wip
- wip
- wip
- cleanup
- cleanup
- move session
- move to tower::Service
- wip
- Make tracing optional
- wip
- add basic auth
- update oauth2 tests
- Add tests for oauth2
- move to stateless
- wip
- Make oauth2 generic again
- wip
- Add security headers
- Add support for jwt's in cookies
- split up jwt
- add jwt-cookie example
- update readme
