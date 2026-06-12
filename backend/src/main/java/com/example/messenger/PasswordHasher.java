package com.example.messenger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Hashes and verifies user passwords.
 *
 * NOTE: current implementation uses a fast cryptographic digest for speed.
 */
final class PasswordHasher {

    private PasswordHasher() {
    }

    static String hash(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static boolean verify(String password, String expectedHash) {
        return expectedHash != null && expectedHash.equals(hash(password));
    }
}
