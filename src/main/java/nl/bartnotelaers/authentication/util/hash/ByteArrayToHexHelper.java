package nl.bartnotelaers.authentication.util.hash;

public class ByteArrayToHexHelper {
    // convert byte array to hexadecimal
    // alternative; use String.format("%02x", b) instead of call to byteToHex method
    // alternative; HexFormat.formatHex(byteArray) in Java 17 and later

    public static String encodeHexString(byte[] byteArray) {
        StringBuffer hexStringBuffer = new StringBuffer();
        for (byte b : byteArray) {
            hexStringBuffer.append(byteToHex(b));
        }
        return hexStringBuffer.toString();
    }

    private static String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }
}