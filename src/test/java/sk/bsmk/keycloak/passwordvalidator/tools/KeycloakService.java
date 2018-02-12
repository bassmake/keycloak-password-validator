package sk.bsmk.keycloak.passwordvalidator.tools;

import org.apache.http.HttpStatus;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import javax.ws.rs.core.Response;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

public class KeycloakService {

  public static final String KEYCLOAK_URL = "http://localhost:8080/auth";
  public static final String REALM = "master";
  public static final String ADMIN_USERNAME = "admin";
  public static final String ADMIN_PASSWORD = "pass";

  private final ResteasyClient resteasyClient;
  private final Keycloak keycloak;

  public KeycloakService() {
    resteasyClient = new ResteasyClientBuilder().connectionPoolSize(10)
      .register(LoggingFilter.class)
      .build();

    keycloak = KeycloakBuilder.builder()
      .resteasyClient(resteasyClient)
      .serverUrl(KEYCLOAK_URL)
      .realm(REALM)
      .clientId("admin-cli")
      .username(ADMIN_USERNAME)
      .password(ADMIN_PASSWORD)
      .grantType(OAuth2Constants.PASSWORD)
      .build();
  }

  public String createUser(String username, String password) {
    final UserRepresentation user = new UserRepresentation();
    user.setEnabled(true);
    user.setUsername(username);
    final CredentialRepresentation credentials = new CredentialRepresentation();
    credentials.setType(CredentialRepresentation.PASSWORD);
    credentials.setValue(password);
    user.setCredentials(Collections.singletonList(credentials));

    final Response response = keycloak
      .realm(REALM)
      .users()
      .create(user);

    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_CREATED);
    return extractCreatedId(response);
  }

  public void deleteUser(String userId) {
    final Response response = keycloak.realm(REALM).users().delete(userId);

    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NO_CONTENT);
  }

  public boolean isPasswordValid(String userId, String password) {

    final CredentialRepresentation credentials = new CredentialRepresentation();
    credentials.setType(CredentialRepresentation.PASSWORD);
    credentials.setValue(password);

    final PasswordValidatorClient validatorClient = resteasyClient.target(KEYCLOAK_URL).proxy(PasswordValidatorClient.class);
    final String authorization = "Bearer " + keycloak.tokenManager().getAccessToken().getToken();
    final Response response = validatorClient.validatePasswordUnauthorized(REALM, userId, credentials);

    return response.getStatus() == HttpStatus.SC_OK;
  }

  public boolean isPasswordValidUnauthorized(String userId, String password) {

    final CredentialRepresentation credentials = new CredentialRepresentation();
    credentials.setType(CredentialRepresentation.PASSWORD);
    credentials.setValue(password);

    final PasswordValidatorClient validatorClient = resteasyClient.target(KEYCLOAK_URL).proxy(PasswordValidatorClient.class);
    final Response response = validatorClient.validatePasswordUnauthorized(REALM, userId, credentials);

    return response.getStatus() == HttpStatus.SC_OK;
  }

  public static String extractCreatedId(Response response) {
    final String location = response.getHeaderString("Location");
    final int index = location.lastIndexOf('/') + 1;
    return location.substring(index);
  }
}
