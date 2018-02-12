# Password validator provider for keycloak

Heavily inspired by https://github.com/keycloak/keycloak/pull/4229.
Before using on production, change logging, as now it logs password.

## Building

- download and extract keycloak (current version is `3.4.3.Final`)
- set admin username as `admin` and password as `pass` - these values are used by tests
- set `KEYCLOAK_HOME` property
- run `./gradlew clean addModule`, this will add module to keycloak
- add `<provider>module:sk.bsmk.keycloak-password-validator</provider>` to <providers> in standalone.xml
- check that provider is deployed in admin console
  - log in as admin
  - go to admin - server info (top right corner)
  - go to providers tab
  - look for `realm-restapi-extension`
- now you can run `./gradlew clean build` with tests as well

## Changing implementation

To upload changed implementation you need to

- run `./gradlew clean removeAndAddModule`
- restart keycloak
