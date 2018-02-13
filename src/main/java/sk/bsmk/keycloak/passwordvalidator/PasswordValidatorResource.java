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

import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class PasswordValidatorResource {

  private final KeycloakSession session;
  private final AuthenticationManager.AuthResult auth;
  private final Logger log = Logger.getLogger(PasswordValidatorResource.class);

  public PasswordValidatorResource(KeycloakSession session) {
    this.session = session;
    this.auth = new AppAuthManager().authenticateBearerToken(session, session.getContext().getRealm());
    if (getRealm() == null) {
      throw new IllegalStateException("The service cannot accept a session without a realm in it's context.");
    }
  }

  @Path("{userId}/password-validation")
  @PUT
  @NoCache
  @Consumes(MediaType.APPLICATION_JSON)
  public Response validatePassword(@PathParam("userId") String userId, CredentialRepresentation pass) {

    checkRealmAdmin();

    log.infof("validating password for user: %s", pass);

    final RealmModel realm = getRealm();
    final UserModel user = session.users().getUserById(userId, realm);

    if (user == null) {
      log.info("user not found");
      throw new NotFoundException("User not found");
    }
    if (pass == null || pass.getValue() == null || !CredentialRepresentation.PASSWORD.equals(pass.getType())) {
      log.info("no password provided");
      throw new BadRequestException("No password provided");
    }
    log.infof("password value: %s", pass.getValue());
    if (isBlank(pass.getValue())) {
      log.info("empty password provided");
      throw new BadRequestException("Empty password not allowed");
    }

    // validate password
    final PasswordPolicyManagerProvider policyManager = session.getProvider(PasswordPolicyManagerProvider.class);
    final PolicyError policyError = policyManager.validate(realm, user, pass.getValue());
    if (null != policyError) {
      log.info("bad password provided");
      throw new BadRequestException("Password does not match");
    }
    log.info("password is ok");
    return Response.ok().build();
  }

  private RealmModel getRealm() {
    return session.getContext().getRealm();
  }

  private void checkRealmAdmin() {
    log.infof("Checking realm", auth);
    if (auth == null) {
      log.info("auth is null");
      throw new NotAuthorizedException("Bearer");
    } else if (auth.getToken().getRealmAccess() == null) {
      log.info("realm access is null");
      throw new ForbiddenException("Does not have realm admin role");
    } else if (!auth.getToken().getRealmAccess().isUserInRole("admin")) {
      log.info("no admin role");
      throw new ForbiddenException("Does not have realm admin role");
    }
  }

  private static boolean isBlank(String s) {
    return s == null || s.trim().length() == 0;
  }

}
