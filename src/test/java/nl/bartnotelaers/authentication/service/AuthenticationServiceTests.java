package nl.bartnotelaers.authentication.service;


import nl.bartnotelaers.authentication.repository.UsernameSaltAndHashMap;
import nl.bartnotelaers.authentication.repository.UsernameTokenDatabase;
import nl.bartnotelaers.authentication.repository.UsernameTokenMap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;

@SpringBootTest
public class AuthenticationServiceTests {
    private AuthenticationService authenticationService;
    private UsernameSaltAndHashMap usernameSaltAndHashMap;
    private UsernameTokenDatabase usernameTokenDatabase;
    private UsernameTokenMap usernameTokenMap;

    @Autowired
    public AuthenticationServiceTests(AuthenticationService authenticationService,
                                      UsernameSaltAndHashMap usernameSaltAndHashMap,
                                      UsernameTokenMap usernameTokenMap) {
        this.authenticationService = authenticationService;
        this.usernameSaltAndHashMap = usernameSaltAndHashMap;
//        this.usernameTokenDatabase = usernameTokenDatabase;
        this.usernameTokenMap = usernameTokenMap;
    }

    @Test
    @DisplayName("valid credentials ; authentication successful")
    public void authenticateTestValidCredentials() {
        // janiceDoe password is  egLi85'x,cZPg%ur
        // hash is sha256 and includes pepper
        usernameSaltAndHashMap.insertUsernameSaltAndHash("janiceDoe",
                "c9a30dea", "5b5f208603f421231b163fdda56b1c337d0bfab9338c20cc9ea66c0d23e11e7e");
        boolean success = authenticationService.authenticate("janiceDoe",
                "egLi85'x,cZPg%ur");
        assert (success);
    }

    @Test
    @DisplayName("invalid credentials ; authentication fails")
    public void authenticateTestInvalidCredentials() {
        // arrange
        // janiceDoe password is  egLi85'x,cZPg%ur
        // hash is sha256 and includes pepper
        usernameSaltAndHashMap.insertUsernameSaltAndHash("janiceDoe",
                "c9a30dea", "5b5f208603f421231b163fdda56b1c337d0bfab9338c20cc9ea66c0d23e11e7e");
        // act
        boolean success = authenticationService.authenticate("janiceDoe", "wrongPassword");
        // assert
        assert (!success);
    }

    @Test
    @DisplayName("Valid UUID token results in successful authentication")
    public void authenticateTokenTestValidUuidToken() {
        String validUuid = UUID.randomUUID().toString();
        usernameTokenMap.insertToken("username", validUuid);
        boolean success = authenticationService.authenticate(validUuid);
        assert (success);
    }

    @Test
    @DisplayName("Invalid UUID token results in failed authentication")
    public void authenticateTokenTestInvalidUuid() {
        boolean success = authenticationService.authenticate("incorrectToken");
        assert (!success);
    }
}
