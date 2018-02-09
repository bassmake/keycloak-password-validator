package sk.bsmk.keycloak.passwordvalidator;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.representations.idm.CredentialRepresentation;
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

  public PasswordValidatorProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Object getResource() {
    return this;
  }

  @Path("{userId}/password-validation")
  @PUT
  @NoCache
  @Consumes(MediaType.APPLICATION_JSON)
  public Response validatePassword(@PathParam("userId") String userId, CredentialRepresentation pass) {

    final RealmModel realm = session.getContext().getRealm();
    final UserModel user = session.users().getUserById(userId, realm);

    if (user == null) {
      throw new NotFoundException("User not found");
    }
    if (pass == null || pass.getValue() == null || !CredentialRepresentation.PASSWORD.equals(pass.getType())) {
      throw new BadRequestException("No password provided");
    }
    if (Validation.isBlank(pass.getValue())) {
      throw new BadRequestException("Empty password not allowed");
    }

    // validate password
    final PasswordPolicyManagerProvider policyManager = session.getProvider(PasswordPolicyManagerProvider.class);
    final PolicyError policyError = policyManager.validate(user.getId(), pass.getValue());
    if (null != policyError) {
      return Response.status(Response.Status.BAD_REQUEST).build();
    }
    return Response.ok().build();
  }

  @Override
  public void close() {
  }
}
