package com.example.messenger;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory user registry: username -> password hash. */
final class UserStore {

    private final Map<String, String> users = new ConcurrentHashMap<>();

    boolean exists(String user) {
        return users.containsKey(user);
    }

    void create(String user, String passwordHash) {
        users.put(user, passwordHash);
    }

    String hashOf(String user) {
        return users.get(user);
    }
}
