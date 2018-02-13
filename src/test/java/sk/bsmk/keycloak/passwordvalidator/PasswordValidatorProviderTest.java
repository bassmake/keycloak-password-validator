package sk.bsmk.keycloak.passwordvalidator;

import org.apache.http.HttpStatus;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import sk.bsmk.keycloak.passwordvalidator.tools.KeycloakService;

import static org.assertj.core.api.Assertions.assertThat;

public class PasswordValidatorProviderTest {

  private static final String PASSWORD = "valid-password";

  private static String userId;
  private static final KeycloakService service = new KeycloakService();

  @BeforeClass
  public static void createUser() {
    userId = service.createUser("someone", "valid-password");
  }

  @AfterClass
  public static void deleteUser() {
    service.deleteUser(userId);
  }

  @Test
  public void thatRequestWithoutTokenReturnsUnauthorized() {
    assertThat(service.validatePasswordUnauthorized(userId, PASSWORD)).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
  }

  @Test
  public void thatValidPasswordReturnsOk() {
    assertThat(service.validatePassword(userId, PASSWORD)).isEqualTo(HttpStatus.SC_OK);
  }

  @Test
  public void thatInvalidPasswordReturnsBadRequest() {
    assertThat(service.validatePassword(userId, "in" + PASSWORD)).isEqualTo(HttpStatus.SC_BAD_REQUEST);
  }

  @Test
  public void thatNonExistingUserReturnsNotFound() {
    assertThat(service.validatePassword("someone-else", "abc")).isEqualTo(HttpStatus.SC_NOT_FOUND);
  }

  @Test
  public void thatEmptyPasswordReturnsBadRequest() {
    assertThat(service.validatePassword(userId, "")).isEqualTo(HttpStatus.SC_BAD_REQUEST);
  }

}
