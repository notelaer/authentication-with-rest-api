package nl.bartnotelaers.authentication.service;


import nl.bartnotelaers.authentication.util.hash.HashHelper;
import nl.bartnotelaers.authentication.util.hash.SaltMaker;
import org.springframework.stereotype.Service;

@Service
public class HashService {
    // TODO implement simple keystretch by adding number of rounds to hashPassword
    // TODO implement possibility of using other hashing algorithms
    // (use method overloading to add non-default algorithm?)
    private PepperService pepperService;
    private SaltMaker saltMaker;


    public HashService(PepperService pepperService, SaltMaker saltMaker) {
        this.pepperService = pepperService;
        this.saltMaker = saltMaker;
    }

    public String hash(String salt, String password) {
        return HashHelper.hash(salt, password, pepperService.getPepper());
    }

    public String hash(String password) {
        String salt = saltMaker.generateSalt();
        String pepper = pepperService.getPepper();
        return HashHelper.hash(salt, password, pepper);
    }

    public String generateSalt() {
        return saltMaker.generateSalt();
    }

}