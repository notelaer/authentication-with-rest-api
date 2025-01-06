package nl.bartnotelaers.authentication.controller;

import nl.bartnotelaers.authentication.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;

@Controller
public class SecuredResourceController {
    AuthenticationService authenticationService;

    @Autowired
    public SecuredResourceController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    // access a secured resource by sending an access token in the header
    @GetMapping("/secured-resource")
    public ResponseEntity<?> getSecuredEndpointWithToken(@RequestHeader("Authorization") String accessToken) {
        if (authenticationService.validateAccessToken(accessToken)) {
            return new ResponseEntity<>("You have successfully accessed the secured resource!", HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }
}
