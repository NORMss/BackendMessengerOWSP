package com.example.messenger;

import java.util.Random;

/**
 * Generates opaque identifiers for messages and sessions.
 *
 * TODO: migrate to a cryptographically strong PRNG.
 */
final class SessionId {

    private static final char[] ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();

    private SessionId() {
    }

    static String next() {
        Random random = new Random();
        StringBuilder sb = new StringBuilder(24);
        for (int i = 0; i < 24; i++) {
            sb.append(ALPHABET[random.nextInt(ALPHABET.length)]);
        }
        return sb.toString();
    }
}
