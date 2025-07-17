package server;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import io.github.cdimascio.dotenv.Dotenv; // Import Dotenv
import com.auth0.jwt.interfaces.DecodedJWT;
import shared.FileMetadata;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.Socket;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class ClientHandler implements Runnable {
    private final SSLSocket socket; // Use SSLSocket
    private BufferedReader reader;
    private PrintWriter writer;
    private String authenticatedUser;
    private SecretKey authenticatedUserFileKey; // Per-user decryption key

    // --- READ FROM ENV VARS ---
    private static String JWT_SECRET;
    private static Algorithm JWT_ALGORITHM;

    static {
        // Load dotenv directly in the static block for this class
        // This ensures JWT_SECRET is available when ClientHandler is first loaded
        Dotenv dotenv = Dotenv.load(); // Load .env file
        JWT_SECRET = dotenv.get("JWT_SECRET"); // Get directly from dotenv instance

        if (JWT_SECRET == null || JWT_SECRET.isEmpty()) {
            System.err.println("ERROR: JWT_SECRET environment variable is not set or is empty in ClientHandler.");
            System.exit(1); // Exit if critical secret is missing
        }
        JWT_ALGORITHM = Algorithm.HMAC256(JWT_SECRET);
    }
    // --------------------------

    private static final long JWT_LIFETIME_SECONDS = TimeUnit.HOURS.toSeconds(1); // Token validity

    public ClientHandler(SSLSocket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            writer = new PrintWriter(socket.getOutputStream(), true);

            String line;
            while ((line = reader.readLine()) != null) {
                String[] command = line.split(" ", 2);
                String cmd = command[0];
                String data = command.length > 1 ? command[1] : "";

                switch (cmd) {
                    case "REGISTER" -> handleRegister(data);
                    case "LOGIN" -> handleLogin(data, socket.getInetAddress().getHostAddress());
                    case "AUTH" -> handleAuthentication(data);
                    case "UPLOAD" -> handleUpload(data);
                    case "LIST" -> handleList();
                    case "DOWNLOAD" -> handleDownload(data);
                    default -> writer.println("ERROR Unknown command");
                }
            }
        } catch (IOException e) {
            System.out.println("[SERVER] Client disconnected from " + socket.getInetAddress().getHostAddress() + ": " + e.getMessage());
        } finally {
            try {
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }
            } catch (IOException e) {
                System.err.println("Error closing client socket: " + e.getMessage());
            }
        }
    }

    private void handleRegister(String data) {
        String[] parts = data.split(" ", 2);
        if (parts.length < 2) {
            writer.println("ERROR Invalid REGISTER format");
            return;
        }
        boolean success = UserManager.register(parts[0], parts[1]);
        writer.println(success ? "OK Registered" : "ERROR User exists or registration failed");
    }

    private void handleLogin(String data, String clientIp) {
        String[] parts = data.split(" ", 2);
        if (parts.length < 2) {
            writer.println("ERROR Invalid LOGIN format");
            return;
        }
        String username = parts[0];
        String password = parts[1];

        if (UserManager.login(username, password, clientIp)) {
            String token = JWT.create()
                    .withSubject(username)
                    .withIssuedAt(Date.from(Instant.now()))
                    .withExpiresAt(Date.from(Instant.now().plusSeconds(JWT_LIFETIME_SECONDS)))
                    .sign(JWT_ALGORITHM);
            writer.println("OK " + token);
        } else {
            writer.println("ERROR Invalid credentials or locked out");
        }
    }

    private void handleAuthentication(String jwtToken) {
        try {
            // No need for this defensive check if static block correctly initializes JWT_ALGORITHM
            // if (JWT_ALGORITHM == null) {
            //     JWT_SECRET = System.getenv("JWT_SECRET");
            //     if (JWT_SECRET == null || JWT_SECRET.isEmpty()) {
            //         writer.println("ERROR Server misconfiguration: JWT secret not loaded.");
            //         this.authenticatedUser = null;
            //         return;
            //     }
            //     JWT_ALGORITHM = Algorithm.HMAC256(JWT_SECRET);
            // }

            DecodedJWT jwt = JWT.require(JWT_ALGORITHM).build().verify(jwtToken);
            this.authenticatedUser = jwt.getSubject();
            this.authenticatedUserFileKey = UserManager.getUserFileKey(authenticatedUser);
            if (this.authenticatedUserFileKey == null) {
                writer.println("ERROR Failed to retrieve user file key");
                this.authenticatedUser = null;
                return;
            }
            writer.println("OK Authenticated");
        } catch (JWTVerificationException e) {
            System.err.println("JWT verification failed: " + e.getMessage());
            writer.println("ERROR Invalid or expired token");
            this.authenticatedUser = null;
        }
    }

    private void handleUpload(String filename) throws IOException {
        if (authenticatedUser == null || authenticatedUserFileKey == null) {
            writer.println("ERROR Not authenticated");
            return;
        }
        writer.println("READY"); // Tell client to send file

        FileManager.receiveEncryptedFile(socket.getInputStream(), authenticatedUser, filename, authenticatedUserFileKey);
        writer.println("OK Upload complete");
    }

    private void handleList() {
        if (authenticatedUser == null) {
            writer.println("ERROR Not authenticated");
            return;
        }
        List<FileMetadata> files = FileManager.listUserFiles(authenticatedUser);
        if (files.isEmpty()) {
            writer.println("No files found for " + authenticatedUser + ".");
        } else {
            for (FileMetadata file : files) {
                writer.println(file.getFilename() + " | " + file.getFileSize() + " bytes | SHA-256: " + file.getSha256Hash());
            }
        }
        writer.println("END");
    }

    private void handleDownload(String filename) throws IOException {
        if (authenticatedUser == null || authenticatedUserFileKey == null) {
            writer.println("ERROR Not authenticated");
            return;
        }
        try {
            FileMetadata metadata = FileManager.getFileMetadata(authenticatedUser, filename);
            if (metadata == null) {
                writer.println("ERROR File not found: " + filename);
                return;
            }

            writer.println("READY");
            writer.println(metadata.getFileSize());

            FileManager.sendDecryptedFile(socket.getOutputStream(), authenticatedUser, filename, authenticatedUserFileKey);

            writer.println("OK Download complete");
        } catch (FileNotFoundException e) {
            writer.println("ERROR File not found: " + e.getMessage());
            System.err.println("Download error for " + filename + ": " + e.getMessage());
        } catch (IOException e) {
            writer.println("ERROR Failed to download file: " + e.getMessage());
            System.err.println("Download error for " + filename + ": " + e.getMessage());
        }
    }
}