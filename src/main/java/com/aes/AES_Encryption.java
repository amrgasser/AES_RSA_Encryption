package com.aes;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AES_Encryption {
    private SecretKey key;
    private final int KEY_SIZE = 128;
    private final int DATA_LENGTH = 128;
    private Cipher encryptionCipher;
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";

    public AES_Encryption() {
        KeyGenerator gen = null;
        try {
            gen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        gen.init(128); //Specify key size bytes
        key = gen.generateKey();
    }

    public SecretKey getKey(){
        return this.key;
    }

    public String encrypt(String data) throws Exception {
        byte[] dataInBytes = data.getBytes();
        encryptionCipher = Cipher.getInstance(ENCRYPT_ALGO);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
        return encode(encryptedBytes);

    }
    public String decrypt(String encryptedData,byte[] inputKey) throws Exception {
        byte[] dataInBytes = decode(encryptedData);
        Cipher decryptionCipher = Cipher.getInstance(ENCRYPT_ALGO);
        GCMParameterSpec spec = new GCMParameterSpec(DATA_LENGTH, encryptionCipher.getIV());

        //Return original key from decoded key
        SecretKey originalKey = new SecretKeySpec(inputKey, "AES");

        decryptionCipher.init(Cipher.DECRYPT_MODE, originalKey, spec);

        byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
        return new String(decryptedBytes);
    }

    protected String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    protected byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }
}
