package com.bjornloftis.dukpt;

import com.bjornloftis.dukpt.ipek.InitialPinEncryptionKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;

public class DukptImpl {

    private static final int IPEK_KEY_LENGTH = 128 / 8;
    public static final String DESEDE_CBC_ZERO_BYTE_PADDING = "DESede/CBC/ZeroBytePadding";
    public static final String DES_ECB_NO_PADDING = "DES/ECB/NoPadding";
    public static final String TRIPLE_DES_KEY_ALGORITHM = "DESede";
    public static final String DES_KEY_ALGORITHM = "DES";
    public static final String INITIALIZATION_VECTOR = "0000000000000000";
    private static byte[] DEK_XORMASK = Hex.decode("0000000000FF00000000000000FF0000");

    private byte[][] keyComponents;
    private byte[] ipekbytes;
    private String ksn;
    private byte[] ksnbytes;

    public DukptImpl(InitialPinEncryptionKey ipek) {
        keyComponents = extractKeyComponents(ipek);
        ipekbytes = assembleIpekFromKeyComponents(keyComponents);
        ksn = ipek.getKsn();
        ksnbytes = Hex.decode(ksn);
        addBouncyCastleProvider();
    }

    public String encryptTrackDataTDEAZeroBytePadding(byte[] trackData) {
        byte[] dataEncryptionKey = createDataEncryptionKey();
        try {
            Cipher c = Cipher.getInstance(DESEDE_CBC_ZERO_BYTE_PADDING, "BC");
            IvParameterSpec ivspec = new IvParameterSpec(Hex.decode(INITIALIZATION_VECTOR));
            SecretKeySpec keyspec = new SecretKeySpec(dataEncryptionKey, TRIPLE_DES_KEY_ALGORITHM);
            c.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
            byte[] ctbytes = new byte[c.getOutputSize(trackData.length)];
            c.doFinal(trackData, 0, trackData.length, ctbytes);
            return new String(Hex.encode(ctbytes));
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | ShortBufferException | InvalidKeyException e) {
            throw new RuntimeException("something ran amok with the data encryption", e);
        }
    }

    public String getDataEncryptionKey() {
        byte[] dataEncryptionKey = createDataEncryptionKey();
        return Hex.toHexString(dataEncryptionKey).toUpperCase();
    }

    private byte[] createDataEncryptionKey() {
        try{
            byte[] derivedKey = generateDerivedKey(ksnbytes, ipekbytes);
            byte[] derivedKeyLeftHalf = createDerivedKeyLeftHalf(derivedKey);
            byte[] derivedKeyRightHalf = createDerivedKeyRightHalf(derivedKey);
            byte[] variantKeyLeft = createVariantKeyLeft(derivedKeyLeftHalf);
            byte[] variantKeyRight = createVariantKeyRight(derivedKeyRightHalf);
            byte[] combinedVariantKey = combineVariantKeys(variantKeyLeft, variantKeyRight);
            return createDataEncryptionKey(combinedVariantKey, variantKeyLeft, variantKeyRight);
        } catch (Exception e){
            throw new RuntimeException("failed to create DEK", e);
        }
    }

    private byte[] createDataEncryptionKey(byte[] combinedVariantKey, byte[] variantLeft, byte[] variantRight) {
        byte[] dek = null;
        try {
            Cipher c = Cipher.getInstance("DESede/ECB/NoPadding", "BC");
            SecretKeySpec keyspec = new SecretKeySpec(combinedVariantKey, "DESede");
            c.init(Cipher.ENCRYPT_MODE, keyspec);
            byte[] ctbytes = new byte[c.getOutputSize(variantLeft.length)];
            int count = c.doFinal(variantLeft, 0, variantLeft.length, ctbytes);
            dek = new byte[ctbytes.length * 2];
            System.arraycopy(ctbytes, 0, dek, 0, count);
            ctbytes = new byte[c.getOutputSize(variantRight.length)];
            count = c.doFinal(variantRight, 0, variantRight.length, ctbytes);
            System.arraycopy(ctbytes, 0, dek, dek.length / 2, count);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | ShortBufferException | InvalidKeyException e) {
            throw new RuntimeException("something ran amok with the encyption creating the DEK", e);
        }
        return dek;
    }

    private byte[] createDerivedKeyRightHalf(byte[] derivedKey) {
        byte[] rightHandDerivedKey = new byte[derivedKey.length / 2];
        System.arraycopy(derivedKey, derivedKey.length / 2, rightHandDerivedKey, 0, derivedKey.length / 2);
        return rightHandDerivedKey;
    }

    private byte[] createDerivedKeyLeftHalf(byte[] derivedKey) {
        byte[] leftHandDerivedKey = new byte[derivedKey.length / 2];
        System.arraycopy(derivedKey, 0, leftHandDerivedKey, 0, derivedKey.length / 2);
        return leftHandDerivedKey;
    }

    private byte[] createVariantKeyLeft(byte[] derivedKeyLeftHalf) {
        byte[] result = new byte[derivedKeyLeftHalf.length];
        for (int i = 0; i < derivedKeyLeftHalf.length; i++) {
            result[i] = (byte) (derivedKeyLeftHalf[i] ^ DEK_XORMASK[i]);
        }
        return result;
    }

    private byte[] createVariantKeyRight(byte[] derivedKeyRightHalf) {
        byte[] result = new byte[derivedKeyRightHalf.length];
        for (int i = 0, j = DEK_XORMASK.length / 2; i < derivedKeyRightHalf.length; i++, j++) {
            result[i] = (byte) (derivedKeyRightHalf[i] ^ DEK_XORMASK[j]);
        }
        return result;
    }

    private byte[] combineVariantKeys(byte[] left, byte[] right) {
        byte[] combinedvk = new byte[left.length + right.length];
        System.arraycopy(left, 0, combinedvk, 0, left.length);
        System.arraycopy(right, 0, combinedvk, left.length, right.length);
        return combinedvk;
    }

    private byte[] generateDerivedKey(byte[] ksnbytes, byte[] ipekbytes) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, ShortBufferException, IllegalBlockSizeException {
        byte[] derivedKey = new byte[16];
        byte[] r8 = initR8(ksnbytes);
        byte[] r3 = initR3(ksnbytes);
        int r3hex = Integer.parseInt(new String(Hex.encode(r3)), 16);
        byte[] r8A = new byte[8];
        byte[] r8B = new byte[8];
        int sr = 0x100000;
        CurKey curKey = new CurKey(ipekbytes);
        while (sr != 0) {
            if ((sr & r3hex) != 0) {
                byte[] srbytes = BigInteger.valueOf(sr).toByteArray();
                for (int i = 0; i < srbytes.length; i++) {
                    r8[r8.length - (i + 1)] = (byte) (r8[r8.length - (i + 1)] | srbytes[srbytes.length - (i + 1)]);
                }
                for (int i = 0; i < r8.length; i++) {
                    r8A[i] = (byte) (r8[i] ^ curKey.rh[i]);
                }
                SecretKeySpec skspec = new SecretKeySpec(curKey.lh, "DES");
                Cipher cdes = Cipher.getInstance(DES_ECB_NO_PADDING, "BC");
                cdes.init(Cipher.ENCRYPT_MODE, skspec);
                byte[] ct = new byte[cdes.getOutputSize(r8A.length)];
                int count = cdes.doFinal(r8A, 0, r8A.length, ct);
                System.arraycopy(ct, 0, r8A, 0, count);
                for (int i = 0; i < r8A.length; i++) {
                    r8A[i] = (byte) (r8A[i] ^ curKey.rh[i]);
                }
                curKey.xorCurkeyAndCocopad();
                for (int i = 0; i < r8.length; i++) {
                    r8B[i] = (byte) (r8[i] ^ curKey.rh[i]);
                }
                skspec = new SecretKeySpec(curKey.lh, DES_KEY_ALGORITHM);
                cdes.init(Cipher.ENCRYPT_MODE, skspec);
                ct = new byte[cdes.getOutputSize(r8B.length)];
                count = cdes.doFinal(r8B, 0, r8B.length, ct);
                System.arraycopy(ct, 0, r8B, 0, count);
                for (int i = 0; i < r8B.length; i++) {
                    r8B[i] = (byte) (r8B[i] ^ curKey.rh[i]);
                }
                curKey.updateCurkey(r8A, r8B);
            }
            sr >>= 1;
            if (sr == 0) {
                System.arraycopy(curKey.key, 0, derivedKey, 0, curKey.key.length);
                break;
            }
        }
        return derivedKey;
    }

    private byte[] initR3(byte[] ksnbytes) {
        byte[] r3 = new byte[3];
        r3[2] = ksnbytes[ksnbytes.length - 1];
        r3[1] = ksnbytes[ksnbytes.length - 2];
        r3[0] = ksnbytes[ksnbytes.length - 3];
        r3[0] = (byte) (r3[0] << 3);
        r3[0] = (byte) (r3[0] >> 3);
        return r3;
    }

    private byte[] initR8(byte[] ksnbytes) {
        byte[] r8 = new byte[8];
        System.arraycopy(ksnbytes, 2, r8, 0, 8);
        r8[6] = (byte) 0;
        r8[7] = (byte) 0;
        r8[5] = (byte) (r8[5] & 0xE0);
        return r8;
    }

    private void addBouncyCastleProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private byte[][] extractKeyComponents(InitialPinEncryptionKey ipek) {
        byte[][] keycompbytes = new byte[128 / 8][3];
        keycompbytes[0] = Hex.decode(ipek.getKeyComponents().get(0).getComponent());
        keycompbytes[1] = Hex.decode(ipek.getKeyComponents().get(1).getComponent());
        keycompbytes[2] = Hex.decode(ipek.getKeyComponents().get(2).getComponent());
        return keycompbytes;
    }

    private byte[] assembleIpekFromKeyComponents(byte[][] keycompbytes) {
        byte[] ipekbytes = new byte[IPEK_KEY_LENGTH];
        byte[] xorbytes = new byte[3];
        for (int i = 0; i < ipekbytes.length; i++) {
            for (int n = 0; n < xorbytes.length; n++) {
                xorbytes[n] = keycompbytes[n][i];
            }
            byte tempbyte1 = xorbytes[0];
            for (int n = 1; n < xorbytes.length; n++) {
                byte tempbyte2 = (byte) (tempbyte1 ^ xorbytes[n]);
                tempbyte1 = tempbyte2;
            }
            ipekbytes[i] = tempbyte1;
        }
        return ipekbytes;
    }
}
