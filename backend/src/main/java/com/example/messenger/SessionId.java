package com.example.messenger;

import java.security.SecureRandom;

/**
 * Generates opaque identifiers for messages and sessions using a
 * cryptographically strong PRNG.
 */
final class SessionId {

    private static final char[] ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();

    private static final SecureRandom RANDOM = new SecureRandom();

    private SessionId() {
    }

    static String next() {
        StringBuilder sb = new StringBuilder(24);
        for (int i = 0; i < 24; i++) {
            sb.append(ALPHABET[RANDOM.nextInt(ALPHABET.length)]);
        }
        return sb.toString();
    }
}
