package sk.bsmk.keycloak.passwordvalidator;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ServerInfoAwareProviderFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import java.util.LinkedHashMap;
import java.util.Map;

public class PasswordValidatorProviderFactory implements RealmResourceProviderFactory, ServerInfoAwareProviderFactory {

  public static final String ID = "password-validator";

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public Map<String, String> getOperationalInfo() {
    final Map<String, String> info = new LinkedHashMap<>();
    info.put("version", "0.3");
    return info;
  }

  @Override
  public RealmResourceProvider create(KeycloakSession session) {
    return new PasswordValidatorProvider(session);
  }

  @Override
  public void init(Config.Scope config) {
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
  }

  @Override
  public void close() {
  }
}
