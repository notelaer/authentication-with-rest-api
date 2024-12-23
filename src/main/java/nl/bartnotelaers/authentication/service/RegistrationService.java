package nl.bartnotelaers.authentication.service;

import nl.bartnotelaers.authentication.repository.Database;
import nl.bartnotelaers.authentication.util.hash.SaltMaker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class RegistrationService {
    private HashService hashService;
    private Database database;

    @Autowired
    public RegistrationService(HashService hashService, Database database) {
        this.hashService = hashService;
        this.database = database;
    }

    public boolean register(String username, String password) {
        String salt = SaltMaker.generateSalt();
        String hashedPassword = hashService.hash(salt, password);
        // return boolean instead of proper exception handling ( not the focus of this project)
        return database.insertUsernameSaltAndHash(username, salt, hashedPassword);
    }
}
