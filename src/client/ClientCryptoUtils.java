// client/ClientCryptoUtils.java
package client;

// This class is a placeholder for client-side cryptographic utilities.
// In the current system design, file encryption/decryption happens on the server side
// using the user's master key. The client sends/receives raw file data over the
// TLS-encrypted socket.
//
// If you were to implement client-side encryption (e.g., for local caching of encrypted files),
// methods for AES encryption/decryption, key derivation, etc., would go here.

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class ClientCryptoUtils {

    /**
     * Calculates the SHA-256 hash of a file.
     * This can be used by the client before uploading to verify integrity after download.
     * @param file The file to hash.
     * @return The Base64 encoded SHA-256 hash string, or null if an error occurs.
     */
    public static String calculateFileSha256(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
            byte[] hashedBytes = digest.digest();
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException | IOException e) {
            System.err.println("Error calculating SHA-256 hash for file: " + e.getMessage());
            return null;
        }
    }

    // Add other client-side crypto methods here if needed (e.g., for client-side key storage/derivation)
}