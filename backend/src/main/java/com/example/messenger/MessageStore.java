package com.example.messenger;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory message inbox keyed by recipient username. */
final class MessageStore {

    private static final class Message {
        final String id;
        final String from;
        final String text;

        Message(String id, String from, String text) {
            this.id = id;
            this.from = from;
            this.text = text;
        }
    }

    private final Map<String, List<Message>> inboxes = new ConcurrentHashMap<>();

    void add(String to, String from, String text, String id) {
        inboxes.computeIfAbsent(to, k -> new ArrayList<>())
                .add(new Message(id, from, text));
    }

    String inboxJson(String user) {
        List<Message> inbox = inboxes.getOrDefault(user, List.of());
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < inbox.size(); i++) {
            Message m = inbox.get(i);
            if (i > 0) {
                sb.append(",");
            }
            sb.append("{\"id\":\"").append(Json.escape(m.id))
                    .append("\",\"from\":\"").append(Json.escape(m.from))
                    .append("\",\"text\":\"").append(Json.escape(m.text))
                    .append("\"}");
        }
        return sb.append("]").toString();
    }
}
