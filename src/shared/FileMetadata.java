// shared/FileMetadata.java
package shared;

import java.io.Serializable;

public class FileMetadata implements Serializable {
    private static final long serialVersionUID = 1L;
    private String filename;
    private long fileSize; // Size of the original, unencrypted file
    private String sha256Hash; // SHA-256 hash of the original, unencrypted file
    private String username;
    private String iv; // IV for AES encryption (Base64 encoded string)

    public FileMetadata(String filename, long fileSize, String sha256Hash, String username, String iv) {
        this.filename = filename;
        this.fileSize = fileSize;
        this.sha256Hash = sha256Hash;
        this.username = username;
        this.iv = iv;
    }

    // Getters
    public String getFilename() {
        return filename;
    }

    public long getFileSize() {
        return fileSize;
    }

    public String getSha256Hash() {
        return sha256Hash;
    }

    public String getUsername() {
        return username;
    }

    public String getIv() {
        return iv;
    }


    public void setFilename(String filename) {
        this.filename = filename;
    }

    public void setFileSize(long fileSize) {
        this.fileSize = fileSize;
    }

    public void setSha256Hash(String sha256Hash) {
        this.sha256Hash = sha256Hash;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    @Override
    public String toString() {
        return filename + " | " + fileSize + " bytes | SHA-256: " + sha256Hash;
    }
}