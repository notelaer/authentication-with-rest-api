package nl.bartnotelaers.authentication.service;

import nl.bartnotelaers.authentication.repository.UsernameSaltAndHashDatabase;
import nl.bartnotelaers.authentication.util.hash.SaltMaker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class RegistrationService {
    private HashService hashService;
    private UsernameSaltAndHashDatabase usernameSaltAndHashDatabase;

    @Autowired
    public RegistrationService(HashService hashService,
                               UsernameSaltAndHashDatabase usernameSaltAndHashDatabase) {
        this.hashService = hashService;
        this.usernameSaltAndHashDatabase = usernameSaltAndHashDatabase;
    }

    public boolean register(String username, String password) {
        String salt = SaltMaker.generateSalt();
        String hashedPassword = hashService.hash(salt, password);
        // return boolean instead of proper exception handling ( not the focus of this project)
        return usernameSaltAndHashDatabase.insertUsernameSaltAndHash(username, salt, hashedPassword);
    }
}
