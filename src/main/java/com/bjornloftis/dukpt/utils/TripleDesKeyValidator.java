package com.bjornloftis.dukpt.utils;


import org.bouncycastle.util.encoders.Hex;

public class TripleDesKeyValidator {

    public static String createCheckValue(String hexDsaKey) {
        TripleDESEncryptor desEncryptor = new TripleDESEncryptor();
        if (hexDsaKey.length() == 48) {
            ;
        } else if (hexDsaKey.length() == 32) {
            hexDsaKey = hexDsaKey + hexDsaKey.substring(0, 16);
        } else {
            throw new RuntimeException("invalid DESede Key Length");
        }
        byte[] plaintext = Hex.decode("0000000000000000");
        byte[] ciphertext = desEncryptor.encryptDES(plaintext, hexDsaKey);
        return Hex.toHexString(ciphertext);
    }

    public static String createSmallCheckValue(String s) {
        String checkValue = createCheckValue(s);
        return checkValue.substring(0, 6).toUpperCase();
    }

}
