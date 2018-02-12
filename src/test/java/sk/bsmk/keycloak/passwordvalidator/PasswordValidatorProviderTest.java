package sk.bsmk.keycloak.passwordvalidator;

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

  }

  @Test
  public void thatValidPasswordReturnsOk() {
    assertThat(service.isPasswordValid(userId, PASSWORD)).isTrue();
  }

  @Test
  public void thatInvalidPasswordReturnsBadRequest() {
    assertThat(service.isPasswordValid(userId, PASSWORD + "abc")).isFalse();
  }

  @Test
  public void thatNonExistingUserReturnsBadRequest() {
    service.isPasswordValid("someone-else", "abc");
  }

  @Test
  public void thatEmptyPasswordReturnsBadRequest() {
    service.isPasswordValid(userId, "");
  }

}
