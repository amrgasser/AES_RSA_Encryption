import com.aes.AES_Encryption;
import com.aes.RSA_Encryption;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class RSA_AES_Application {

    public static void main(String[] args) throws Exception{
        AES_Encryption aesEncryption = new AES_Encryption();
        RSA_Encryption rsaEncryption = new RSA_Encryption();

        String aesKeyToString = Base64.getEncoder().encodeToString(aesEncryption.getKey().getEncoded());
        System.out.println("Your AES encryption key: "+aesKeyToString);

        System.out.println("Enter Text to Encrypt:");
        String textToEncrypt = JOptionPane.showInputDialog("Type a secret message here: ");;

        String aesEncrypted = aesEncryption.encrypt(textToEncrypt);
        System.out.println("Your AES Encrypted Text is:\n"+aesEncrypted);

        byte[] rsaEncryptedKey = rsaEncryption.encrypt(aesEncryption.getKey().getEncoded());
        System.out.println("Your RSA encrypted AES key that will be sent with the message:\n"+new String(rsaEncryptedKey));
        Thread.sleep(1000);
        System.out.println("Now we will decrypt the AES key with the private RSA key...");
        Thread.sleep(1000);

        byte[] aesDecryptedKey = rsaEncryption.decrypt(rsaEncryptedKey);
        System.out.println("Decrypted AES key:\n"+new String(aesDecryptedKey, StandardCharsets.UTF_8));

        String output = aesEncryption.decrypt(aesEncrypted,aesDecryptedKey);
        System.out.println("After Decryption: "+output);
        JOptionPane.showMessageDialog(null,"Is this your message?\n"+output);

    }
}
