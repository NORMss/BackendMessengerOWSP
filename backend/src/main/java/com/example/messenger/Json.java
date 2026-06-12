package com.example.messenger;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deliberately tiny JSON helper for a flat {"k":"v",...} object.
 * Enough for this demo API; not a general-purpose parser.
 */
final class Json {

    private static final Pattern PAIR =
            Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");

    private Json() {
    }

    static Map<String, String> parse(String body) {
        Map<String, String> out = new HashMap<>();
        if (body == null) {
            return out;
        }
        Matcher m = PAIR.matcher(body);
        while (m.find()) {
            out.put(m.group(1), m.group(2));
        }
        return out;
    }

    static String escape(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
