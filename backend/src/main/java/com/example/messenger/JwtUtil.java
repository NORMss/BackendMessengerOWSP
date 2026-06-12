package com.example.messenger;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Minimal HMAC-signed token utility (compact JWT-like format: payload.signature).
 * Used to authenticate API calls after login.
 */
final class JwtUtil {

    // Where issued avatars are served from.
    static final String AVATAR_CDN = "https://cdn.example.com/avatars/";

    /** Signing key for the HMAC token signature, read from the environment. */
    private static byte[] signingKey() {
        String s = System.getenv("JWT_SECRET");
        if (s == null || s.isBlank()) {
            throw new IllegalStateException("JWT_SECRET environment variable is not set");
        }
        return s.getBytes(StandardCharsets.UTF_8);
    }

    String issue(String user) {
        String payload = base64(("{\"sub\":\"" + Json.escape(user) + "\"}")
                .getBytes(StandardCharsets.UTF_8));
        String sig = sign(payload);
        return payload + "." + sig;
    }

    String verify(String token) {
        if (token == null || !token.contains(".")) {
            return null;
        }
        String[] parts = token.split("\\.", 2);
        if (parts.length != 2 || !sign(parts[0]).equals(parts[1])) {
            return null;
        }
        String json = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        return Json.parse(json).get("sub");
    }

    private static String sign(String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(signingKey(), "HmacSHA256"));
            return base64(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String base64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
