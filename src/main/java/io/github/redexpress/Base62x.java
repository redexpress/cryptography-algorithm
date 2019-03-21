package io.github.redexpress;

import java.util.Base64;

public class Base62x {
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
}
