package nl.bartnotelaers.authentication.service;


import nl.bartnotelaers.authentication.repository.UsernameSaltAndHashMap;
import nl.bartnotelaers.authentication.repository.UsernameTokenDatabase;
import nl.bartnotelaers.authentication.repository.UsernameTokenMap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

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
    @DisplayName("Validate simple JWT token")
    public void validateJwtToken() {
        // arrange
        String validJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJKb2huIERvZSIsInRva2VuIjoic29tZVRva2VuVG9TdG9yZSIsImlhdCI6MTUxNjIzOTAyMn0.whJVj1qjPyUxPc4QzlYk5eeQ2vP_A0Qw6khx5p7Dy2I";
        usernameTokenMap.insertToken("John Doe", "someTokenToStore");
        // act
        boolean success = authenticationService.validateJwt(validJwt);
        // assert
        assert (success);
    }

    @Test
    @DisplayName("Reject expired AccessToken")
    public void validateAccessTokenRejectExpired() {
        // arrange
        // JWT contains expiration date somewhere in 2018
        String expiredJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJKaW1teSBKb2huc29uIiwidG9rZW4iOiJzb21lVG9rZW5Ub1N0b3JlIiwiZXhwIjoxNTE2MjM5MDIyfQ.ozIEjP0XK2C5SsCaDNZ8WNDhdwXbl0QQL_dxXAjTXwQ";
        usernameTokenMap.insertToken("Jimmy Johnson", "someTokenToStore");
        assert (usernameTokenMap.hasToken("someTokenToStore"));
        // act
        boolean success = authenticationService.validateAccessToken(expiredJwt);
        // assert
        assert (!success);
    }

    @Test
    @DisplayName("Create token and validate immediately (requires working validateAccessToken)")
    public void createAccessTokenAndValidate() {
        // arrange
        String newToken = authenticationService.createAccessToken("Joanna Doe");
        // act
        boolean success = authenticationService.validateAccessToken(newToken);
        // assert
        assert (success);
    }



}
