package sk.bsmk.keycloak.passwordvalidator.tools;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.representations.idm.CredentialRepresentation;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public interface PasswordValidatorClient {

  @Path("realms/{realm}/password-validator/{userId}/password-validation")
  @PUT
  @NoCache
  @Consumes(MediaType.APPLICATION_JSON)
  Response validatePassword(
    @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
    @PathParam("realm") String realm,
    @PathParam("userId") String userId,
    CredentialRepresentation pass
  );


  @Path("realms/{realm}/password-validator/{userId}/password-validation")
  @PUT
  @NoCache
  @Consumes(MediaType.APPLICATION_JSON)
  Response validatePasswordUnauthorized(
    @PathParam("realm") String realm,
    @PathParam("userId") String userId,
    CredentialRepresentation pass
  );

}
