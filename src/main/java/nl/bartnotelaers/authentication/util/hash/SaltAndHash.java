package nl.bartnotelaers.authentication.util.hash;

/**
 *  helper class for storing salt+hash in MapDatabase
 */
public class SaltAndHash {
    private String salt;
    private String hash;

    public SaltAndHash(String salt, String hash) {
        this.salt = salt;
        this.hash = hash;
    }

    public String getSalt() {
        return salt;
    }

    public String getHash() {
        return hash;
    }
}
