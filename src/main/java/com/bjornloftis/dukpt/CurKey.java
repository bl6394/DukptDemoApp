package com.bjornloftis.dukpt;

import org.bouncycastle.util.encoders.Hex;

class CurKey {
    static byte[] COCOPAD = Hex.decode("C0C0C0C000000000C0C0C0C000000000");

    public byte[] key = new byte[16];
    public byte[] rh = new byte[8];
    public byte[] lh = new byte[8];

    public CurKey(byte[] ipek) {
        System.arraycopy(ipek, 0, key, 0, ipek.length);
        System.arraycopy(ipek, 0, lh, 0, ipek.length / 2);
        System.arraycopy(ipek, ipek.length / 2, rh, 0, ipek.length / 2);
    }

    public final void xorCurkeyAndCocopad() {
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (key[i] ^ COCOPAD[i]);
        }
        System.arraycopy(key, 0, lh, 0, key.length / 2);
        System.arraycopy(key, key.length / 2, rh, 0, key.length / 2);
    }

    public final void updateCurkey(byte[] R8A, byte[] R8B) {
        System.arraycopy(R8B, 0, key, 0, R8B.length);
        System.arraycopy(R8B, 0, lh, 0, R8B.length);
        System.arraycopy(R8A, 0, key, R8A.length, R8A.length);
        System.arraycopy(R8A, 0, rh, 0, R8A.length);
    }


}
