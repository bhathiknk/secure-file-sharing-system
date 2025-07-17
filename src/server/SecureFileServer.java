package server;

import io.github.cdimascio.dotenv.Dotenv;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;

public class SecureFileServer {
    public static final int PORT = 5000;
    private static final String KEYSTORE_PATH = "certs/server.keystore";
    private static String KEYSTORE_PASSWORD;

    public static void main(String[] args) {
        System.out.println("[SERVER] Starting Secure File Server on port " + PORT);

        // Load environment variables at the very beginning of main
        Dotenv dotenv = Dotenv.load();
        KEYSTORE_PASSWORD = dotenv.get("SERVER_KEYSTORE_PASSWORD"); // Get directly from dotenv instance

        // Validate environment variables
        if (KEYSTORE_PASSWORD == null || KEYSTORE_PASSWORD.isEmpty()) {
            System.err.println("ERROR: SERVER_KEYSTORE_PASSWORD environment variable is not set or is empty.");
            System.err.println("Please set it before running the server (e.g., in your .env file or command line).");
            System.exit(1);
        }

        SSLServerSocketFactory ssf;
        try {
            // Load the keystore
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
                ks.load(fis, KEYSTORE_PASSWORD.toCharArray());
            }

            // Set up KeyManagerFactory to use the keystore
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); // Use default algorithm// Use default algorithm
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            // Initialize SSLContext
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(kmf.getKeyManagers(), null, null);

            ssf = sc.getServerSocketFactory();
        } catch (Exception e) {
            System.err.println("Failed to initialize SSL: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        try (SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(PORT)) {
            serverSocket.setEnabledCipherSuites(new String[]{"TLS_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"});
            serverSocket.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});

            System.out.println("[SERVER] SSL Server Socket created. Waiting for clients...");

            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                System.out.println("[SERVER] Client connected: " + clientSocket.getInetAddress());
                new Thread(new ClientHandler(clientSocket)).start();
            }
        } catch (IOException e) {
            System.err.println("Server socket error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}