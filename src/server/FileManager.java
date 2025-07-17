// server/FileManager.java
package server;

import shared.FileMetadata;
import java.io.*;
import java.nio.file.*;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import javax.crypto.SecretKey;

public class FileManager {
    private static final String BASE_DIR = "storage/files/";
    private static final String METADATA_FILE_SUFFIX = "_metadata.txt";

    public static void receiveEncryptedFile(InputStream in, String username, String filename, SecretKey userFileKey) throws IOException {
        Path userDir = Paths.get(BASE_DIR, username);
        Files.createDirectories(userDir);
        Path filePath = userDir.resolve(filename);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int len;

            while ((len = in.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
                if (in.available() == 0 && len < buffer.length) {
                    break;
                }
            }

            byte[] fileContent = baos.toByteArray();
            String fileHash = CryptoUtils.calculateFileHash(fileContent); // Hash of original content

            // Generate a new IV for each file encryption
            byte[] iv = CryptoUtils.generateIv();
            byte[] encrypted = CryptoUtils.encryptFile(fileContent, userFileKey, iv); // Pass IV to encryptFile

            Files.write(filePath, encrypted);

            // Store IV along with other metadata
            // Changed Base664 to Base64
            saveMetadata(username, new FileMetadata(filename, fileContent.length, fileHash, username, Base64.getEncoder().encodeToString(iv)));
        } catch (Exception e) {
            System.err.println("Error receiving encrypted file: " + e.getMessage());
            throw new IOException("File upload failed", e);
        }
    }

    public static void sendDecryptedFile(OutputStream out, String username, String filename, SecretKey userFileKey) throws IOException {
        Path filePath = Paths.get(BASE_DIR, username, filename);
        if (!Files.exists(filePath)) {
            throw new FileNotFoundException("File not found on server: " + filename);
        }

        try {
            byte[] encrypted = Files.readAllBytes(filePath);
            FileMetadata metadata = getFileMetadata(username, filename);

            if (metadata == null) {
                throw new IOException("Metadata not found for file: " + filename);
            }

            // Decode IV from Base64 string
            byte[] iv = Base64.getDecoder().decode(metadata.getIv());

            byte[] decrypted = CryptoUtils.decryptFile(encrypted, userFileKey, iv); // Pass IV to decryptFile

            // Verify integrity before sending
            if (!CryptoUtils.calculateFileHash(decrypted).equals(metadata.getSha256Hash())) {
                System.err.println("File integrity check failed for " + filename + " (user: " + username + ")");
                throw new IOException("File integrity check failed.");
            }

            out.write(decrypted);
            out.flush();
        } catch (Exception e) {
            System.err.println("Error sending decrypted file: " + e.getMessage());
            throw new IOException("File download failed", e);
        }
    }

    public static List<FileMetadata> listUserFiles(String username) {
        Path metaFile = Paths.get(BASE_DIR, username, username + METADATA_FILE_SUFFIX);
        List<FileMetadata> list = new ArrayList<>();
        if (!Files.exists(metaFile)) return list;

        try (BufferedReader br = Files.newBufferedReader(metaFile)) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",", 5);
                if (parts.length == 5) {
                    list.add(new FileMetadata(parts[0], Long.parseLong(parts[1]), parts[2], parts[3], parts[4]));
                }
            }
        } catch (IOException e) {
            System.err.println("Error listing user files: " + e.getMessage());
        }
        return list;
    }

    private static void saveMetadata(String username, FileMetadata metadata) {
        Path userDir = Paths.get(BASE_DIR, username);
        try {
            Files.createDirectories(userDir);
            Path metaFile = userDir.resolve(username + METADATA_FILE_SUFFIX);
            try (BufferedWriter bw = Files.newBufferedWriter(metaFile, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                bw.write(metadata.getFilename() + "," + metadata.getFileSize() + "," + metadata.getSha256Hash() + "," + metadata.getUsername() + "," + metadata.getIv());
                bw.newLine();
            }
        } catch (IOException e) {
            System.err.println("Error saving metadata for user " + username + ": " + e.getMessage());
        }
    }

    public static FileMetadata getFileMetadata(String username, String filename) {
        Path metaFile = Paths.get(BASE_DIR, username, username + METADATA_FILE_SUFFIX);
        if (!Files.exists(metaFile)) return null;

        try (BufferedReader br = Files.newBufferedReader(metaFile)) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",", 5);
                if (parts.length == 5 && parts[0].equals(filename)) {
                    return new FileMetadata(parts[0], Long.parseLong(parts[1]), parts[2], parts[3], parts[4]);
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading metadata for file " + filename + " (user: " + username + "): " + e.getMessage());
        }
        return null;
    }
}