import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AES {
    public static void generateSessionKey (String sessionKeyFileName, String algorithm, int keyLengthBits) throws NoSuchAlgorithmException, IOException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keyLengthBits);
        var key= keyGenerator.generateKey().getEncoded();

        File sessionKeyFile = new File(sessionKeyFileName);
        if (!sessionKeyFile.exists()) {
            sessionKeyFile.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(sessionKeyFile);
        fos.write(key);
        fos.close();
    }

    public static void AES_ECBencrypt (String keyFileName, String toEncryptFilename, String encryptedFileName) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        File toEncryptFile = new File(toEncryptFilename);
        if (!toEncryptFile.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream fis = new FileInputStream(toEncryptFile);
        BufferedInputStream bis = new BufferedInputStream(fis);
        var toBeEncrypted = bis.readAllBytes();
        bis.close();

        //get key
        File keyFile = new File(keyFileName);
        if (!keyFile.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream keyfis = new FileInputStream(keyFile);
        var aesKey = keyfis.readAllBytes();
        keyfis.close();

        //encrypt
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        var encrypted = cipher.doFinal(toBeEncrypted);

        //write to file
        File encryptedFile = new File(encryptedFileName);
        if (!encryptedFile.exists()) {
            encryptedFile.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(encryptedFile);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        bos.write(encrypted);
        bos.close();
    }

    public static void AES_ECBdecrypt (String encryptedFileName, String keyFilename, String decryptedFilename) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        File encryptedFile = new File(encryptedFileName);
        if (!encryptedFile.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream fis = new FileInputStream(encryptedFile);
        BufferedInputStream bis = new BufferedInputStream(fis);
        var encrypted = bis.readAllBytes();
        bis.close();

        //get key
        File keyFile = new File(keyFilename);
        if (!keyFile.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream keyfis = new FileInputStream(keyFile);
        var aesKey = keyfis.readAllBytes();
        keyfis.close();

        //decrypt
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        var decrypted = cipher.doFinal(encrypted);

        //write to file
        File decryptedFile = new File(decryptedFilename);
        if (!encryptedFile.exists()) {
            encryptedFile.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(decryptedFile);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        bos.write(decrypted);
        bos.close();

    }
}
