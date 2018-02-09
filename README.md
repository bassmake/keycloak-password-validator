# Password validator provider for keycloak

Heavily inspired by https://github.com/keycloak/keycloak/pull/4229.

## Building

- download and extract keycloak (current version is `3.4.3.Final`)
- set `KEYCLOAK_HOME`
- run `./gradlew clean copyJar`, this will copy jar to keycloak deployments folder
- check that provider is deployed in admin console
  - log in as admin
  - go to admin - server info (top right corner)
  - go to providers tab
  - look for `realm-restapi-extension`
- now you can run `./gradlew clean build` with tests as well
