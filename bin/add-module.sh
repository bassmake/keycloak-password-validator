#!/usr/bin/env bash
$KEYCLOAK_HOME/bin/jboss-cli.sh --command="module add --name=sk.bsmk.keycloak-password-validator --resources=../build/libs/keycloak-password-validator.jar --dependencies=org.keycloak.keycloak-core,org.keycloak.keycloak-services,org.keycloak.keycloak-server-spi,org.keycloak.keycloak-server-spi-private,javax.ws.rs.api,org.jboss.logging"
