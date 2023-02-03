import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class Main {
    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException {
        File file = new File("marakeystore.ks");
        if(!file.exists()) {
            System.out.println("NO SUCH FILE!!!");
            throw new FileNotFoundException();
        }
        FileInputStream fis = new FileInputStream(file);

        String ksPass = "marapass";

        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(fis, ksPass.toCharArray());

        fis.close();
        RSA.checkSign("SAPExamSubject1.txt", ks, "ismasero", "SAPExamSubject1.signature", "SHA512withRSA");
        RSA.checkSign("SAPExamSubject2.txt", ks, "ismasero", "SAPExamSubject2.signature", "SHA512withRSA");
        RSA.checkSign("SAPExamSubject3.txt", ks, "ismasero", "SAPExamSubject3.signature", "SHA512withRSA");

        //AES.generateSessionKey("aes_key.key", "AES", 128);

        AES.AES_ECBencrypt("aes_key.key", "response.txt", "response.sec");
        AES.AES_ECBdecrypt("response.sec", "test_key.key", "testresponse.txt");
        //RSA.encryptKey("aes_key.key", "aes_key.sec", ks, "ismasero");

        //testing with my certificate
        //RSA.encryptKey("aes_key.key", "test_key.sec", ks, "marakey");
        //RSA.decryptKey("test_key.sec", "test_key.key", ks, "marakey");
        //RSA.encryptWithPrivate("aes_key.key", "aes_key_enc_with_my_private_key.sec", ks, "marakey");
        //RSA.decryptWithPublic("aes_key_enc_with_my_private_key.sec", "aes_key_dec_with_public.key", ks, "marakey");

    }
}
