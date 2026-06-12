package com.example.messenger;

import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Hashes and verifies user passwords with PBKDF2-HMAC-SHA256 and a per-user
 * random salt. The stored format is "iterations:saltBase64:hashBase64".
 */
final class PasswordHasher {

    private static final int ITERATIONS = 210_000;
    private static final int KEY_LENGTH = 256;
    private static final int SALT_BYTES = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHasher() {
    }

    static String hash(String password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] dk = pbkdf2(password, salt, ITERATIONS);
        return ITERATIONS + ":"
                + Base64.getEncoder().encodeToString(salt) + ":"
                + Base64.getEncoder().encodeToString(dk);
    }

    static boolean verify(String password, String stored) {
        if (stored == null) {
            return false;
        }
        String[] parts = stored.split(":");
        if (parts.length != 3) {
            return false;
        }
        int iterations = Integer.parseInt(parts[0]);
        byte[] salt = Base64.getDecoder().decode(parts[1]);
        byte[] expected = Base64.getDecoder().decode(parts[2]);
        byte[] actual = pbkdf2(password, salt, iterations);
        return constantTimeEquals(expected, actual);
    }

    private static byte[] pbkdf2(String password, byte[] salt, int iterations) {
        try {
            KeySpec spec = new PBEKeySpec(
                    password.toCharArray(), salt, iterations, KEY_LENGTH);
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
}
