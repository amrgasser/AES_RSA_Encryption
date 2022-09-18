import com.aes.AES_Encryption;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Scanner;

public class AESApplication {

    public static void main(String[] args) throws Exception{
        Scanner myObj = new Scanner(System.in);
        AES_Encryption aesEncryption = new AES_Encryption();

        System.out.println("Enter Encryption Key:");
        String key = myObj.nextLine();
        SecretKey aesEncryptionKey =aesEncryption.getAESKeyFromUser(key.toCharArray(),getRandomNonce(16));
        System.out.println("Your encryption key: "+aesEncryptionKey.toString());

        System.out.println("Enter Text to Encrypt:");
        String textToEncrypt = myObj.nextLine();
        System.out.println("Your Text is: "+textToEncrypt);

        String encrypted = aesEncryption.encrypt(textToEncrypt);
        System.out.println("Your Encrypted Text is: "+encrypted);

        String decrypted = aesEncryption.decrypt(encrypted);
        System.out.println("Your Encrypted Text is: "+decrypted);

    }


    public static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }
}
