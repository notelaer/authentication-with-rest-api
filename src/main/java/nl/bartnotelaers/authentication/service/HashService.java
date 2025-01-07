package nl.bartnotelaers.authentication.service;


import com.auth0.jwt.algorithms.Algorithm;
import nl.bartnotelaers.authentication.util.hash.HashHelper;
import nl.bartnotelaers.authentication.util.hash.SaltMaker;
import org.springframework.stereotype.Service;

@Service
public class HashService {
    // TODO implement simple keystretch by adding number of rounds to hash method
    // or play with bcrypt
    private PepperService pepperService;

    // secret used by algorithm for singing and verifying jwt (see environment variables)
    // not secure for production though :-)
    private final String SECRET = System.getenv("JWT_SECRET");

    // algorithm to use with singing and verifying JWT
    // TODO implement possibility of using other hashing algorithms?
    //  and then check for algorithm in JWT header when validating
    private final Algorithm algorithm = Algorithm.HMAC256(SECRET);

    public HashService(PepperService pepperService) {
        this.pepperService = pepperService;
    }

    public String hash(String salt, String password) {
        return HashHelper.hash(salt, password, pepperService.getPepper());
    }

    public String hash(String password) {
        String salt = SaltMaker.generateSalt();
        String pepper = pepperService.getPepper();
        return HashHelper.hash(salt, password, pepper);
    }

    public String generateSalt() {
        return SaltMaker.generateSalt();
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }
}