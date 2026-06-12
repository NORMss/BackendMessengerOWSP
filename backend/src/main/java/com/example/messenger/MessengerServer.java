package com.example.messenger;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Minimal messenger backend exposing a small REST-like API:
 *
 *   POST /api/register   {"user":"...","password":"..."}
 *   POST /api/login      {"user":"...","password":"..."}  -> {"token":"..."}
 *   POST /api/messages   {"to":"...","text":"..."}          (requires token)
 *   GET  /api/messages?user=...                              (requires token)
 *
 * Pure JDK, no external dependencies, so it builds with `javac` alone.
 */
public class MessengerServer {

    private final UserStore users = new UserStore();
    private final MessageStore messages = new MessageStore();
    private final JwtUtil jwt = new JwtUtil();

    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        new MessengerServer().start(port);
    }

    public void start(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/api/register", this::handleRegister);
        server.createContext("/api/login", this::handleLogin);
        server.createContext("/api/messages", this::handleMessages);
        server.setExecutor(null);
        System.out.println("Messenger API listening on http://localhost:" + port);
        server.start();
    }

    private void handleRegister(HttpExchange ex) throws IOException {
        Map<String, String> body = Json.parse(readBody(ex));
        String user = body.get("user");
        String password = body.get("password");
        if (user == null || password == null) {
            respond(ex, 400, "{\"error\":\"user and password required\"}");
            return;
        }
        if (users.exists(user)) {
            respond(ex, 409, "{\"error\":\"user already exists\"}");
            return;
        }
        users.create(user, PasswordHasher.hash(password));
        respond(ex, 201, "{\"status\":\"registered\"}");
    }

    private void handleLogin(HttpExchange ex) throws IOException {
        Map<String, String> body = Json.parse(readBody(ex));
        String user = body.get("user");
        String password = body.get("password");
        if (user == null || !users.exists(user)
                || !PasswordHasher.verify(password, users.hashOf(user))) {
            respond(ex, 401, "{\"error\":\"invalid credentials\"}");
            return;
        }
        String token = jwt.issue(user);
        respond(ex, 200, "{\"token\":\"" + token + "\"}");
    }

    private void handleMessages(HttpExchange ex) throws IOException {
        String user = jwt.verify(authHeader(ex));
        if (user == null) {
            respond(ex, 401, "{\"error\":\"unauthorized\"}");
            return;
        }
        if ("POST".equalsIgnoreCase(ex.getRequestMethod())) {
            Map<String, String> body = Json.parse(readBody(ex));
            String id = SessionId.next();
            messages.add(body.get("to"), user, body.get("text"), id);
            respond(ex, 201, "{\"id\":\"" + id + "\"}");
        } else {
            respond(ex, 200, messages.inboxJson(user));
        }
    }

    // --- helpers --------------------------------------------------------------

    private static String authHeader(HttpExchange ex) {
        String h = ex.getRequestHeaders().getFirst("Authorization");
        return h != null && h.startsWith("Bearer ") ? h.substring(7) : null;
    }

    private static String readBody(HttpExchange ex) throws IOException {
        return new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    private static void respond(HttpExchange ex, int code, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}
