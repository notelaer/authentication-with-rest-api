package nl.bartnotelaers.authentication.controller;

import nl.bartnotelaers.authentication.model.Credential;
import nl.bartnotelaers.authentication.service.RegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
public class RegistrationController {
    private RegistrationService registrationService;

    @Autowired
    public RegistrationController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    // register a new user
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Credential credential) {
        System.out.println(credential.toString());
        String username = credential.getUsername();
        String password = credential.getPassword();
        if (registrationService.register(username, password)) {
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.CONFLICT);
        }
    }
}
