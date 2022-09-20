package com.aes;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

/**
 * @author Taoyimin
 * @create 2019 05 07 20:25
 */
public class RSA_Encryption {
    private static PublicKey publicKey;
    private static PrivateKey privateKey;

    public RSA_Encryption() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
    }

    public byte[] encrypt(byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptCipher.init(Cipher.PUBLIC_KEY, publicKey);
        byte[] encryptedMessageBytes = encryptCipher.doFinal(message);

        return encryptedMessageBytes;
    }

    public byte[] decrypt(byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.PRIVATE_KEY, privateKey);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(message);
        return decryptedMessageBytes;
    }


}