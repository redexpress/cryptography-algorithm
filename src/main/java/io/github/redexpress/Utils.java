package io.github.redexpress;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utils {

    public byte[] ripemd160(byte[] input){
        RIPEMD160Digest d = new RIPEMD160Digest();
        d.update(input, 0, input.length);
        byte[] o = new byte[d.getDigestSize()];
        d.doFinal(o, 0);
        return o;
    }

    public static byte[] sha256(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(input);
            return md.digest();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
