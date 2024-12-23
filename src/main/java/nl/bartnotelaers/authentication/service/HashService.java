package nl.bartnotelaers.authentication.service;


import nl.bartnotelaers.authentication.util.hash.HashHelper;
import org.springframework.stereotype.Service;

@Service
public class HashService {
    // TODO implement simple keystretch by adding number of rounds to hash
    // TODO implement possibility of using other hashing algorithms
    private PepperService pepperService;

    public HashService(PepperService pepperService) {
        this.pepperService = pepperService;
    }

    public String hash(String salt, String password) {
        return HashHelper.hash(salt, password, pepperService.getPepper());
    }

}