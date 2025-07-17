package client;

import io.github.cdimascio.dotenv.Dotenv; // Import Dotenv

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.util.List;
import java.util.Scanner;

public class SecureFileClient {

    private static final String SERVER_IP = "localhost";
    private static final int SERVER_PORT = 5000;
    private static final String TRUSTSTORE_PATH = "certs/client.truststore";
    // --- READ FROM ENV VARS ---
    private static String TRUSTSTORE_PASSWORD; // Declare as non-final
    // ---------------------

    // ANSI Color Codes
    public static final String RESET = "\u001B[0m";
    public static final String BLACK = "\u001B[30m";
    public static final String RED = "\u001B[31m";
    public static final String GREEN = "\u001B[32m";
    public static final String YELLOW = "\u001B[33m";
    public static final String BLUE = "\u001B[34m";
    public static final String PURPLE = "\u001B[35m";
    public static final String CYAN = "\u001B[36m";
    public static final String WHITE = "\u001B[37m";

    // ANSI Background Colors (less common for text highlighting, but useful)
    public static final String BLACK_BACKGROUND = "\u001B[40m";
    public static final String RED_BACKGROUND = "\u001B[41m";
    public static final String GREEN_BACKGROUND = "\u001B[42m";
    public static final String YELLOW_BACKGROUND = "\u001B[43m";
    public static final String BLUE_BACKGROUND = "\u001B[44m";
    public static final String PURPLE_BACKGROUND = "\u001B[45m";
    public static final String CYAN_BACKGROUND = "\u001B[46m";
    public static final String WHITE_BACKGROUND = "\u001B[47m";

    // ANSI Text Styles
    public static final String BOLD = "\u001B[1m";
    public static final String UNDERLINE = "\u001B[4m";
    public static final String BLINK = "\u001B[5m"; // May not work in all terminals

    public static void main(String[] args) {
        // Load environment variables at the very beginning of main
        Dotenv dotenv = Dotenv.load();
        TRUSTSTORE_PASSWORD = dotenv.get("CLIENT_TRUSTSTORE_PASSWORD"); // Get directly from dotenv instance

        // Validate environment variables
        if (TRUSTSTORE_PASSWORD == null || TRUSTSTORE_PASSWORD.isEmpty()) {
            System.err.println(RED + "ERROR: CLIENT_TRUSTSTORE_PASSWORD environment variable is not set or is empty." + RESET);
            System.err.println(RED + "Please set it before running the client (e.g., in your .env file or command line)." + RESET);
            System.exit(1);
        }

        SSLSocketFactory sslSocketFactory = null;
        try {
            KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
            try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
                ts.load(fis, TRUSTSTORE_PASSWORD.toCharArray());
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, tmf.getTrustManagers(), null);
            sslSocketFactory = sc.getSocketFactory();

        } catch (Exception e) {
            System.err.println(RED + "Failed to initialize SSL for client: " + e.getMessage() + RESET);
            e.printStackTrace();
            System.exit(1);
        }

        try (SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(SERVER_IP, SERVER_PORT);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             Scanner scanner = new Scanner(System.in)) {

            socket.startHandshake(); // This is where the Connection reset happens
            System.out.println(GREEN + BOLD + "Connected to server securely (TLS)." + RESET);

            CommandHandler commandHandler = new CommandHandler(in, out, socket.getInputStream(), socket.getOutputStream());

            while (true) {
                System.out.println(CYAN + "\n--- Commands ---" + RESET);
                System.out.println(YELLOW + "REGISTER <username> <password>");
                System.out.println("LOGIN <username> <password>");
                System.out.println(GREEN + "UPLOAD <local_file_path>");
                System.out.println("DOWNLOAD <filename> <output_path>");
                System.out.println(PURPLE + "LIST");
                System.out.println(RED + "LOGOUT");
                System.out.println("EXIT" + RESET); // Reset after the last command

                commandHandler.printAuthStatus();
                System.out.print(BLUE + "Enter command: " + RESET);
                String input = scanner.nextLine().trim();

                String[] parts = input.split(" ", 3);
                String command = parts[0].toUpperCase();

                String clientDisplayMessage = "";

                try {
                    switch (command) {
                        case "REGISTER":
                            if (parts.length == 3) {
                                clientDisplayMessage = commandHandler.register(parts[1], parts[2]);
                            } else {
                                clientDisplayMessage = RED + "Usage: REGISTER <username> <password>" + RESET;
                            }
                            break;
                        case "LOGIN":
                            if (parts.length == 3) {
                                clientDisplayMessage = commandHandler.login(parts[1], parts[2]);
                            } else {
                                clientDisplayMessage = RED + "Usage: LOGIN <username> <password>" + RESET;
                            }
                            break;
                        case "UPLOAD":
                            if (parts.length == 2) {
                                clientDisplayMessage = commandHandler.uploadFile(parts[1]);
                            } else {
                                clientDisplayMessage = RED + "Usage: UPLOAD <local_file_path>" + RESET;
                            }
                            break;
                        case "DOWNLOAD":
                            if (parts.length == 3) {
                                clientDisplayMessage = commandHandler.downloadFile(parts[1], parts[2]);
                            } else {
                                clientDisplayMessage = RED + "Usage: DOWNLOAD <filename> <output_path>" + RESET;
                            }
                            break;
                        case "LIST":
                            try {
                                List<String> files = commandHandler.listFiles();
                                if (files.isEmpty()) {
                                    clientDisplayMessage = YELLOW + "No files found for " + commandHandler.getCurrentUsername() + "." + RESET;
                                } else {
                                    System.out.println(CYAN + "--- Your Files ---" + RESET);
                                    for (String fileEntry : files) {
                                        System.out.println(GREEN + fileEntry + RESET); // Color file entries
                                    }
                                    clientDisplayMessage = GREEN + "File list received successfully." + RESET;
                                }
                            } catch (IOException e) {
                                clientDisplayMessage = RED + "Error listing files: " + e.getMessage() + RESET;
                            }
                            break;
                        case "LOGOUT":
                            clientDisplayMessage = commandHandler.logout();
                            break;
                        case "EXIT":
                            System.out.println(RED + "Exiting client..." + RESET);
                            return;
                        default:
                            clientDisplayMessage = RED + "Unknown command." + RESET;
                    }

                    if (!clientDisplayMessage.isEmpty()) {
                        System.out.println("Client Response: " + clientDisplayMessage);
                    }

                } catch (IOException e) {
                    System.err.println(RED + "Communication error with server: " + e.getMessage() + RESET);
                    e.printStackTrace();
                    break;
                } catch (Exception e) {
                    System.err.println(RED + "An unexpected error occurred during command execution: " + e.getMessage() + RESET);
                    e.printStackTrace();
                }
            }

        } catch (IOException e) {
            System.err.println(RED + "Client connection error: " + e.getMessage() + RESET);
            e.printStackTrace();
        }
    }
}