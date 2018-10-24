package com.bjornloftis.dukpt.utils;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class TripleDESEncryptor {

    public byte[] encryptDES (byte [] plaintext, String key){

        Cipher desCipher;
        byte[] ciphertext = null;
        try {
            byte[] keyBytes = Hex.decode(key);
            final SecretKey desEdeKey = new SecretKeySpec(keyBytes, "DESede");
            desCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            desCipher.init(Cipher.ENCRYPT_MODE, desEdeKey);
            ciphertext = desCipher.doFinal(plaintext);


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return ciphertext;
    }

    public void decrypt(){

    }
}
