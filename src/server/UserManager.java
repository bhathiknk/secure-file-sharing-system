package server;

import java.io.*;
import java.nio.file.*;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;

public class UserManager {
    private static final Path USERS_FILE = Paths.get("storage/users.txt");
    // Format: username,hashed_password,salt_base64,encrypted_file_key_base64
    private static final Map<String, User> users = new ConcurrentHashMap<>();
    private static final Map<String, Integer> loginAttempts = new ConcurrentHashMap<>();
    private static final Map<String, Long> lockedOutUsers = new ConcurrentHashMap<>(); // IP or username -> lockout end time
    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_MINUTES = 5;

    static {
        try {
            Files.createDirectories(USERS_FILE.getParent());
            loadUsers();
        } catch (IOException e) {
            System.err.println("Error initializing UserManager: " + e.getMessage());
        }
    }

    private static void loadUsers() {
        if (!Files.exists(USERS_FILE)) return;
        try (BufferedReader br = Files.newBufferedReader(USERS_FILE)) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",", 4);
                if (parts.length == 4) {
                    String username = parts[0];
                    String hashedPassword = parts[1];
                    byte[] salt = Base64.getDecoder().decode(parts[2]);
                    String encryptedFileKey = parts[3];
                    users.put(username, new User(username, hashedPassword, salt, encryptedFileKey));
                }
            }
        } catch (IOException e) {
            System.err.println("Error loading users: " + e.getMessage());
        }
    }

    public static boolean register(String username, String password) {
        if (users.containsKey(username)) return false;

        try {
            byte[] salt = CryptoUtils.generateSalt();
            String hashedPassword = CryptoUtils.hashPassword(password, salt);
            SecretKey userFileKey = CryptoUtils.generateUserFileKey();
            String encryptedUserFileKey = CryptoUtils.encryptUserKey(userFileKey);

            User newUser = new User(username, hashedPassword, salt, encryptedUserFileKey);
            users.put(username, newUser);

            try (BufferedWriter bw = Files.newBufferedWriter(USERS_FILE, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                bw.write(username + "," + hashedPassword + "," + Base64.getEncoder().encodeToString(salt) + "," + encryptedUserFileKey);
                bw.newLine();
            }
            return true;
        } catch (Exception e) {
            System.err.println("Error during registration for user " + username + ": " + e.getMessage());
            return false;
        }
    }

    public static boolean login(String username, String password, String clientIp) {
        // Check for IP lockout
        if (isLockedOut(clientIp)) {
            System.out.println("Login attempt from locked out IP: " + clientIp);
            return false;
        }

        User user = users.get(username);
        if (user == null) {
            recordFailedAttempt(clientIp); // Account for non-existent users
            return false;
        }

        String hashedPassword = CryptoUtils.hashPassword(password, user.getSalt());
        if (hashedPassword.equals(user.getHashedPassword())) {
            resetLoginAttempts(clientIp);
            return true;
        } else {
            recordFailedAttempt(clientIp);
            return false;
        }
    }

    public static SecretKey getUserFileKey(String username) {
        User user = users.get(username);
        if (user == null) return null;
        try {
            return CryptoUtils.decryptUserKey(user.getEncryptedFileKey());
        } catch (Exception e) {
            System.err.println("Error decrypting file key for user " + username + ": " + e.getMessage());
            return null;
        }
    }

    private static void recordFailedAttempt(String identifier) {
        loginAttempts.merge(identifier, 1, Integer::sum);
        if (loginAttempts.get(identifier) >= MAX_LOGIN_ATTEMPTS) {
            lockedOutUsers.put(identifier, System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(LOCKOUT_DURATION_MINUTES));
            System.out.println("Locked out " + identifier + " for " + LOCKOUT_DURATION_MINUTES + " minutes.");
        }
    }

    private static void resetLoginAttempts(String identifier) {
        loginAttempts.remove(identifier);
        lockedOutUsers.remove(identifier);
    }

    private static boolean isLockedOut(String identifier) {
        Long lockoutEndTime = lockedOutUsers.get(identifier);
        if (lockoutEndTime != null) {
            if (System.currentTimeMillis() < lockoutEndTime) {
                return true; // Still locked out
            } else {
                lockedOutUsers.remove(identifier); // Lockout expired
                loginAttempts.remove(identifier); // Reset attempts after lockout
            }
        }
        return false;
    }

    // Inner class to hold user details
    private static class User {
        private final String username;
        private final String hashedPassword;
        private final byte[] salt;
        private final String encryptedFileKey; // Base64 encoded

        public User(String username, String hashedPassword, byte[] salt, String encryptedFileKey) {
            this.username = username;
            this.hashedPassword = hashedPassword;
            this.salt = salt;
            this.encryptedFileKey = encryptedFileKey;
        }

        public String getUsername() {
            return username;
        }

        public String getHashedPassword() {
            return hashedPassword;
        }

        public byte[] getSalt() {
            return salt;
        }

        public String getEncryptedFileKey() {
            return encryptedFileKey;
        }
    }
}