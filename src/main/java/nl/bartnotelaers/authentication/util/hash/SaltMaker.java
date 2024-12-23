package nl.bartnotelaers.authentication.util.hash;

import java.security.SecureRandom;

public class SaltMaker {
    private static final int DEFAULT_SALT_LENGTH = 8;

    public static String generateSalt() {
        return generateSalt(DEFAULT_SALT_LENGTH);
    }

    public static String generateSalt(int saltLength) {
        SecureRandom sr = new SecureRandom();
        // set up size
        // beware; every byte input wil result in 2 hexadecimal output
        byte[] arr = new byte[saltLength];
        // fill array with secure random byte values
        sr.nextBytes(arr);
        // encode byte array to String
        String hexString = ByteArrayToHexHelper.encodeHexString(arr);
        // or (Java 17 and later) HexFormat.formatHex
        return hexString;
    }
}
