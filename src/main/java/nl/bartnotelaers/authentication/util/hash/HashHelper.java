package nl.bartnotelaers.authentication.util.hash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashHelper {
    //  SHA-256 is not safe to use in production!
    //  this is just for study and practice purposes
    private static final String HASHING_ALGORITHM = "SHA-256";

    public static String hash(String password) {
        try {
            // set up MessageDigest instance with a hashing algorithm
            MessageDigest md = MessageDigest.getInstance(HASHING_ALGORITHM);
            // add input (multiple updates are possible, see method below)
            md.update(password.getBytes(StandardCharsets.UTF_8));
            // process input to a hash (digest)
            byte[] digest = md.digest();
            // encode digest to hexadecimal
            return ByteArrayToHexHelper.encodeHexString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException();
        }
    }

    // duplicated code for gentle difficulty curve :-)
    public static String hash(String salt, String password, String pepper) {
        try {
            // set up MessageDigest instance with a hashing algorithm
            MessageDigest md = MessageDigest.getInstance(HASHING_ALGORITHM);
            // add password, salt and pepper (can be in any order)
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            md.update(password.getBytes(StandardCharsets.UTF_8));
            md.update(pepper.getBytes(StandardCharsets.UTF_8));
            // process input to a hash (digest)
            byte[] digest = md.digest();
            // encode digest to hexadecimal
            return ByteArrayToHexHelper.encodeHexString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException();
        }
    }
}