package sk.bsmk.keycloak.passwordvalidator;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.validation.Validation;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class PasswordValidatorProvider implements RealmResourceProvider {

  private final KeycloakSession session;
  private final AuthenticationManager.AuthResult auth;
  private final Logger log = Logger.getLogger(PasswordValidatorProvider.class);

  public PasswordValidatorProvider(KeycloakSession session) {
    this.session = session;
    this.auth = new AppAuthManager().authenticateBearerToken(session, session.getContext().getRealm());
  }

  @Override
  public Object getResource() {
    return this;
  }

  @Path("/{userId}/password-validation")
  @PUT
  @NoCache
  @Consumes(MediaType.APPLICATION_JSON)
  public Response validatePassword(@PathParam("userId") String userId, CredentialRepresentation pass) {

    log.infof("Validating password for user: %s", pass);

    final RealmModel realm = session.getContext().getRealm();
    final UserModel user = session.users().getUserById(userId, realm);

    if (user == null) {
      log.info("user not found");
      throw new NotFoundException("User not found");
    }
    if (pass == null || pass.getValue() == null || !CredentialRepresentation.PASSWORD.equals(pass.getType())) {
      log.info("no password provided");
      throw new BadRequestException("No password provided");
    }
    log.infof("Password value: %s", pass.getValue());
    if (Validation.isBlank(pass.getValue())) {
      log.info("empty password provided");
      throw new BadRequestException("Empty password not allowed");
    }

    // validate password
    final PasswordPolicyManagerProvider policyManager = session.getProvider(PasswordPolicyManagerProvider.class);
    final PolicyError policyError = policyManager.validate(user.getId(), pass.getValue());
    if (null != policyError) {
      log.info("password not provided");
      return Response.status(Response.Status.BAD_REQUEST).build();
    }
    return Response.ok().build();
  }

  @Override
  public void close() {
  }
}
