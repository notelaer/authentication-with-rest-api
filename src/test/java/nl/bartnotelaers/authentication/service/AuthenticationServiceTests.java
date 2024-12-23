package nl.bartnotelaers.authentication.service;


import nl.bartnotelaers.authentication.repository.MapDatabase;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class AuthenticationServiceTests {
    private final AuthenticationService authenticationService;
    private final MapDatabase mapDatabase;

    @Autowired
    public AuthenticationServiceTests(AuthenticationService authenticationService,
                                      MapDatabase mapDatabase) {
        this.authenticationService = authenticationService;
        this.mapDatabase = mapDatabase;
    }

    @Test
    @DisplayName("authenticate success & fail with valid & invalid credentials")
    public void authenticateTest() {
        // arrange
        // janiceDoe password is  egLi85'x,cZPg%ur
        // hash is sha256 and includes pepper
        mapDatabase.insertUsernameSaltAndHash("janiceDoe",
                "c9a30dea", "5b5f208603f421231b163fdda56b1c337d0bfab9338c20cc9ea66c0d23e11e7e");
        // act
        boolean validAuthentication = authenticationService.authenticate("janiceDoe", "egLi85'x,cZPg%ur");
        boolean invalidAuthentication = authenticationService.authenticate("janiceDoe", "wrongPassword");
        // assert
        assert (validAuthentication);
        assert (!invalidAuthentication);
    }
}
