package sk.bsmk.keycloak.passwordvalidator;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class PasswordValidatorProvider implements RealmResourceProvider {

  private final KeycloakSession session;

  public PasswordValidatorProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Object getResource() {
    return new PasswordValidatorResource(session);
  }

  @Override
  public void close() {
  }

}
