package io.github.redexpress;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

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

    public static String base58encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }
        String alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        int zeroCount = 0;
        StringBuilder zeros = new StringBuilder();
        while (zeroCount < input.length && input[zeroCount] == 0) {
            ++zeroCount;
            zeros.append('1');
        }

        StringBuilder sb = new StringBuilder();

        BigInteger i = null;
        if (input[zeroCount] < 0) {
            byte[] bts = new byte[input.length - zeroCount + 1];
            System.arraycopy(input,zeroCount + 1, bts, 2,input.length - zeroCount - 1);
            int unsignedValue = input[zeroCount] + 2 * Byte.MAX_VALUE + 2;
            bts[0] = (byte)((unsignedValue >> 8) & 0xff);
            bts[1] = (byte)(unsignedValue & 0xff);
            i = new BigInteger(bts);
        } else {
            i = new BigInteger(input, zeroCount, input.length - zeroCount);
        }
        while(i.intValue() != 0) {
            int remainder = i.mod(BigInteger.valueOf(58)).intValue();
            sb.append(alphabet.charAt(remainder));
            i = i.divide(BigInteger.valueOf(58));
        }
        return zeros.append(sb.reverse().toString()).toString();
    }

    public static byte[] base58decode(String input) {
        if (input.length() == 0) {
            return new byte[0];
        }
        String alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        int zeroCount = 0;
        StringBuilder zeros = new StringBuilder();
        while (zeroCount < input.length() && input.charAt(zeroCount) == '1') {
            ++zeroCount;
        }
        if (input.length() == zeroCount) {
            return new byte[zeroCount];
        }
        byte[] value = input.substring(zeroCount).getBytes(StandardCharsets.US_ASCII);
        for(int i = 0; i < value.length; i++) {
            value[i] = (byte)(alphabet.indexOf(value[i]));
        }
        if (value.length == 1){
            byte[] result = new byte[zeroCount +  1];
            result[zeroCount] = value[0];
            return result;
        }
        BigInteger v = BigInteger.valueOf(value[0]);
        for(int i = 1; i < value.length; i++) {
            v = v.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(value[i]));
        }
        byte[] resultBytes = v.toByteArray();
        byte[] result = new byte[zeroCount +  resultBytes.length];
        System.arraycopy(resultBytes, 0, result, zeroCount, resultBytes.length);
        return result;
    }

    public static String encodeToBase62xString(byte[] bytes) {
        String str = Base64.getEncoder().encodeToString(bytes);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            String base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            String base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwyz";
            char c = str.charAt(i);
            int idx = base64.indexOf(c);
            if (idx < 61) {
                sb.append(base62.charAt(idx));
            } else if (idx == 61) {
                sb.append("x1");
            } else if (idx == 62) {
                sb.append("x2");
            } else if (idx == 63) {
                sb.append("x3");
            }
        }
        return sb.toString();
    }

    public static byte[] merge(byte[] a, byte[] b){
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    public static byte[] merge(byte bt, byte[] b){
        byte[] a = new byte[1];
        a[0] = bt;
        return merge(a, b);
    }

    public static byte[] merge(byte a[], byte bt){
        byte[] b = new byte[1];
        b[0] = bt;
        return merge(a, b);
    }

    public static byte[] hex2byte(String s){
        return new BigInteger(s, 16).toByteArray();
    }
}
