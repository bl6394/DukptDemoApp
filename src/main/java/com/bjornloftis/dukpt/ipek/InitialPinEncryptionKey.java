package com.bjornloftis.dukpt.ipek;


import com.bjornloftis.dukpt.utils.TripleDesKeyValidator;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class InitialPinEncryptionKey {

    private final List<HexKeyComponent> keyComponents;
    private final String checkValue;
    private final String ksn;
    private static final byte[] KSN_MASK = Hex.decode("FFFFFFFFFFFFFFE00000");
    private static final byte[] IPEK_RIGHT_HALF_XOR_MASK = Hex.decode("C0C0C0C000000000C0C0C0C000000000");

    public InitialPinEncryptionKey(BaseDerivationKey baseDerivationKey, String ksn){
        byte[] ipek = generateIPEK(baseDerivationKey, ksn);
        this.keyComponents = createKeyComponents(ipek);
        this.checkValue = TripleDesKeyValidator.createSmallCheckValue(Hex.toHexString(ipek));
        this.ksn = ksn;
    }

    private byte[] generateIPEK(BaseDerivationKey baseDerivationKey, String ksn) {
        List<HexKeyComponent> keyComponents = baseDerivationKey.getKeyComponents();
        String component0 = keyComponents.get(0).getComponent();
        String component1 = keyComponents.get(1).getComponent();
        String component2 = keyComponents.get(2).getComponent();
        String bdk = XorHelper.xorKeyComponents(new BinaryKeyComponent(component0), new BinaryKeyComponent(component1), new BinaryKeyComponent(component2));
        String bdk24Byte = bdk + bdk.substring(0, 16);
        byte[] maskedKSN = andByteArrayWithKsnMask(Hex.decode(ksn));
        byte[] ksn8Byte = new byte[8];
        System.arraycopy(maskedKSN, 0, ksn8Byte, 0,8);
        byte[] ipekLeftHalf = tDesEncrypt(Hex.decode(bdk24Byte), ksn8Byte);
        byte[] ipekRightHalf = createIpekRightHalf(Hex.decode(bdk));
        byte[] ipekRightHalf24Byte = new byte[24];
        System.arraycopy(ipekRightHalf, 0, ipekRightHalf24Byte, 0, 16);
        System.arraycopy(ipekRightHalf, 0, ipekRightHalf24Byte, 16, 8);
        byte[] ipekRightHalfFinal = tDesEncrypt(ipekRightHalf24Byte, ksn8Byte);
        byte[] ipek = new byte[16];
        System.arraycopy(ipekLeftHalf, 0, ipek, 0, 8);
        System.arraycopy(ipekRightHalfFinal, 0, ipek, 8, 8);
        return ipek;
    }

    public List<HexKeyComponent> getKeyComponents() {
        return keyComponents;
    }

    public String getCheckValue() {
        return checkValue;
    }

    public String getKsn() {
        return ksn;
    }

    @Override
    public String toString() {
        return "InitialPinEncryptionKey{" +
                "keyComponents=" + keyComponents +
                ", checkValue='" + checkValue + '\'' +
                ", ksn='" + ksn + '\'' +
                '}';
    }

    private byte[] andByteArrayWithKsnMask (byte[] ksn) {
        byte[] result = new byte[ksn.length];
        for (int i = 0; i < ksn.length; i++) {
            result[i] = (byte) (ksn[i] & KSN_MASK[i]);
        }
        return result;
    }

    private byte[] tDesEncrypt(byte[] key, byte[] plainText) {
        byte[] result = null;
        try {
            final SecretKey secretKey = new SecretKeySpec(key, "DESede");
            final IvParameterSpec iv = new IvParameterSpec(Hex.decode("0000000000000000"));
            final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            result = cipher.doFinal(plainText);
        } catch (Exception e) {
            throw new RuntimeException("wtf", e);
        }
        return  result;
    }

    private byte[] createIpekRightHalf(byte[] bdk) {
        byte[] result = new byte[bdk.length];
        for (int i = 0; i < bdk.length; i++) {
            result[i] = (byte) (bdk[i] ^ IPEK_RIGHT_HALF_XOR_MASK[i]);
        }
        return result;
    }

    private byte[] xor(byte[] a, byte[] b){
        if (a.length != b.length){
            throw new IllegalArgumentException("must be bitfields of the same size");
        }
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    private List<HexKeyComponent> createKeyComponents(byte[] bdk){
        Random rand = new Random();
        byte[] rawKey1 = new byte[bdk.length];
        rand.nextBytes(rawKey1);
        HexKeyComponent component1 = new HexKeyComponent(Hex.toHexString(rawKey1).toUpperCase(), TripleDesKeyValidator.createSmallCheckValue(Hex.toHexString(rawKey1)));
        byte[] rawKey2 = new byte[bdk.length];
        rand.nextBytes(rawKey2);
        HexKeyComponent component2 = new HexKeyComponent(Hex.toHexString(rawKey2).toUpperCase(), TripleDesKeyValidator.createSmallCheckValue(Hex.toHexString(rawKey2)));
        byte[] intermediateValue = xor(rawKey1, rawKey2);
        byte[] rawKey3 = xor(intermediateValue, bdk);
        HexKeyComponent component3 = new HexKeyComponent(Hex.toHexString(rawKey3).toUpperCase(), TripleDesKeyValidator.createSmallCheckValue(Hex.toHexString(rawKey3)));
        List<HexKeyComponent> keyComponents = new ArrayList<>();
        keyComponents.add(component1);
        keyComponents.add(component2);
        keyComponents.add(component3);
        return keyComponents;
    }

    private static int getBit(int position, byte value) {
        return (value >> position) & 0x01;
    }

    private static byte setBit(int position, byte aByte){
        return (byte) (aByte | (1 << position));
    }

}
