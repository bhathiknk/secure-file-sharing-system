// client/CommandHandler.java
package client;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class CommandHandler {
    private BufferedReader in;
    private PrintWriter out;
    private InputStream socketInputStream;
    private OutputStream socketOutputStream;
    private String jwtToken = null;
    private String currentUsername = null;

    public CommandHandler(BufferedReader in, PrintWriter out, InputStream socketInputStream, OutputStream socketOutputStream) {
        this.in = in;
        this.out = out;
        this.socketInputStream = socketInputStream;
        this.socketOutputStream = socketOutputStream;
    }

    public String getCurrentUsername() {
        return currentUsername;
    }

    public boolean isLoggedIn() {
        return jwtToken != null && currentUsername != null;
    }

    public String register(String username, String password) throws IOException {
        out.println("REGISTER " + username + " " + password);
        String response = in.readLine();
        if (response.startsWith("OK")) {
            return "OK: User '" + username + "' registered successfully.";
        }
        return response;
    }

    public String login(String username, String password) throws IOException {
        out.println("LOGIN " + username + " " + password);
        String response = in.readLine();
        if (response.startsWith("OK ")) {
            this.jwtToken = response.substring(3).trim();
            this.currentUsername = username;
            return "OK: Logged in as '" + username + "'. JWT received.";
        }
        return response;
    }

    public String logout() {
        this.jwtToken = null;
        this.currentUsername = null;
        return "OK: Logged out successfully.";
    }

    private String authenticateAndGetResponse(String initialCommand) throws IOException {
        if (!isLoggedIn()) {
            return "ERROR: Not logged in.";
        }
        out.println("AUTH " + jwtToken);
        String authResponse = in.readLine();
        if (!authResponse.startsWith("OK Authenticated")) {
            this.jwtToken = null;
            this.currentUsername = null;
            return "ERROR: Authentication failed. Please re-login.";
        }
        out.println(initialCommand);
        return in.readLine();
    }

    public String uploadFile(String localFilePath) throws IOException {
        File localFile = new File(localFilePath);
        if (!localFile.exists() || !localFile.isFile()) {
            return "ERROR: Local file not found or is not a file: " + localFilePath;
        }

        String fileName = localFile.getName();
        String initialResponse = authenticateAndGetResponse("UPLOAD " + fileName);

        if ("READY".equals(initialResponse)) {
            // Send file content
            try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(localFile))) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = bis.read(buffer)) != -1) {
                    socketOutputStream.write(buffer, 0, bytesRead);
                }
                socketOutputStream.flush(); // Ensure all data is sent

            }
            // Read the final status after file transfer
            return in.readLine();
        } else {
            return initialResponse;
        }
    }

    public String downloadFile(String fileName, String outputPath) throws IOException {
        String initialResponse = authenticateAndGetResponse("DOWNLOAD " + fileName);

        if ("READY".equals(initialResponse)) {
            //  Read the expected file size
            String fileSizeStr = in.readLine();
            long expectedFileSize;
            try {
                expectedFileSize = Long.parseLong(fileSizeStr);
            } catch (NumberFormatException e) {
                // If server sends non-numeric size, it's an error
                System.err.println("Error: Server sent invalid file size: " + fileSizeStr);
                return "ERROR: Invalid file size received from server.";
            }

            Path filePath = Paths.get(outputPath);
            Files.createDirectories(filePath.getParent());

            try (BufferedOutputStream bos = new BufferedOutputStream(Files.newOutputStream(filePath))) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                long totalBytesRead = 0;

                // Read exactly `expectedFileSize` bytes
                while (totalBytesRead < expectedFileSize && (bytesRead = socketInputStream.read(buffer, 0, (int) Math.min(buffer.length, expectedFileSize - totalBytesRead))) != -1) {
                    bos.write(buffer, 0, bytesRead);
                    totalBytesRead += bytesRead;
                }
                bos.flush();

                // Check if all expected bytes were read
                if (totalBytesRead != expectedFileSize) {
                    System.err.println("Warning: Expected " + expectedFileSize + " bytes but read " + totalBytesRead + " bytes for file " + fileName + ".");
                    return "ERROR: Incomplete download. Expected " + expectedFileSize + " bytes, received " + totalBytesRead + ".";
                }

                System.out.println("DEBUG (Download): Successfully read " + totalBytesRead + " bytes for file " + fileName + ".");
            }
            // Read the final status after file transfer
            return in.readLine();
        } else {
            return initialResponse;
        }
    }

    public List<String> listFiles() throws IOException {
        String currentLine = authenticateAndGetResponse("LIST");
        List<String> fileEntries = new ArrayList<>();

        if (currentLine.startsWith("No files found")) {
            in.readLine(); // Consume "END" line
            return fileEntries;
        } else if (currentLine.startsWith("ERROR")) {
            throw new IOException("Server error during list operation: " + currentLine);
        }

        fileEntries.add(currentLine);

        while ((currentLine = in.readLine()) != null) {
            if (currentLine.equals("END")) {
                break;
            }
            if (currentLine.startsWith("ERROR")) {
                throw new IOException("Server error during list operation: " + currentLine);
            }
            fileEntries.add(currentLine);
        }

        return fileEntries;
    }

    public void printAuthStatus() {
        if (isLoggedIn()) {
            System.out.println("Logged in as: " + currentUsername + " (JWT active)");
        } else {
            System.out.println("Not logged in.");
        }
    }
}