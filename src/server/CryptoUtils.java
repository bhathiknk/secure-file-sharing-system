package server;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoUtils {

    private static final String ALGO_TRANSFORMATION = "AES/GCM/NoPadding"; // Using GCM for authenticity
    private static final String ALGO_NAME = "AES"; // Just the algorithm name
    private static final int KEY_SIZE = 256; // AES-256
    private static final int GCM_IV_LENGTH = 12; // Standard IV length for GCM
    private static final int GCM_TAG_LENGTH = 128; // Standard tag length for GCM (in bits, 128 is typical)
    private static final Path MASTER_KEY_FILE = Paths.get("storage/master.key");

    private static SecretKey masterKey;

    static {
        try {
            Files.createDirectories(MASTER_KEY_FILE.getParent());
            loadOrCreateMasterKey();
        } catch (IOException | NoSuchAlgorithmException e) {
            System.err.println("Failed to load or create master key: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void loadOrCreateMasterKey() throws IOException, NoSuchAlgorithmException {
        if (Files.exists(MASTER_KEY_FILE)) {
            byte[] keyBytes = Files.readAllBytes(MASTER_KEY_FILE);
            masterKey = new SecretKeySpec(keyBytes, ALGO_NAME);
        } else {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGO_NAME);
            keyGen.init(KEY_SIZE, new SecureRandom());
            masterKey = keyGen.generateKey();
            Files.write(MASTER_KEY_FILE, masterKey.getEncoded());
            System.out.println("Generated new master key and saved to " + MASTER_KEY_FILE);
        }
    }

    public static SecretKey generateUserFileKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGO_NAME);
        keyGen.init(KEY_SIZE, new SecureRandom());
        return keyGen.generateKey();
    }

    public static byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // Encrypts data using a specific user's file key and an IV
    public static byte[] encryptFile(byte[] data, SecretKey userFileKey, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance(ALGO_TRANSFORMATION);
        //  Use GCMParameterSpec
        c.init(Cipher.ENCRYPT_MODE, userFileKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        return c.doFinal(data);
    }

    // Decrypts data using a specific user's file key and an IV
    public static byte[] decryptFile(byte[] encryptedData, SecretKey userFileKey, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance(ALGO_TRANSFORMATION);
        //  Use GCMParameterSpec
        c.init(Cipher.DECRYPT_MODE, userFileKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        return c.doFinal(encryptedData);
    }

    public static String encryptUserKey(SecretKey userKey) throws Exception {
        Cipher c = Cipher.getInstance(ALGO_NAME + "/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, masterKey);
        byte[] encryptedKeyBytes = c.doFinal(userKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKeyBytes);
    }

    public static SecretKey decryptUserKey(String encryptedUserKeyBase64) throws Exception {
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedUserKeyBase64);
        Cipher c = Cipher.getInstance(ALGO_NAME + "/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, masterKey);
        byte[] decryptedKeyBytes = c.doFinal(encryptedKeyBytes);
        return new SecretKeySpec(decryptedKeyBytes, ALGO_NAME);
    }

    public static String hashPassword(String password, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] digest = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    public static String calculateFileHash(byte[] fileContent) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(fileContent);
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}