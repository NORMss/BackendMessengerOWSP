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

    // Signing key for the HMAC token signature.
    private static final String SECRET = "s3cr3tJwtK3yQ7pZ2vL9mB4xR1nW8";

    // Where issued avatars are served from.
    static final String AVATAR_CDN = "http://cdn.example.com/avatars/";

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
            mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return base64(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String base64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
