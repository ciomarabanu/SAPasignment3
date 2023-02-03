import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;

public class RSA {
    public static void checkSign(String originalFileName,
                                 KeyStore keyStore,
                                 String certificateAlias,
                                 String signatureFilename,
                                 String signAlgorithm)
        throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, KeyStoreException {
        File originalFile = new File(originalFileName);
        if (!originalFile.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream fis = new FileInputStream(originalFile);

        byte[] originalFileContent = fis.readAllBytes();
        fis.close();

        //get public key from certificate
        PublicKey publicKey = keyStore.getCertificate(certificateAlias).getPublicKey();

        Signature verify = Signature.getInstance(signAlgorithm);
        verify.initVerify(publicKey);
        verify.update(originalFileContent);

        File signFile = new File(signatureFilename);
        FileInputStream sigFis = new FileInputStream(signFile);
        byte[] digitalSignature = sigFis.readAllBytes();
        fis.close();

        System.out.println(originalFileName + " validity is: " + verify.verify(digitalSignature));
    }

    public static void encryptKey(String keyFilename,
                                  String encryptedFeyFilename,
                                  KeyStore keyStore,
                                  String certificateAlias) throws KeyStoreException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        //get prof public key from keystore
        PublicKey publicKey = keyStore.getCertificate(certificateAlias).getPublicKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //encrypt
        File keyFile = new File(keyFilename);
        if (!keyFile.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream fis =  new FileInputStream(keyFile);
        var aes_key = fis.readAllBytes();
        var encryptedKey = cipher.doFinal(aes_key);
        fis.close();

        //write to file
        File encryptedKeyFile = new File(encryptedFeyFilename);
        if (!encryptedKeyFile.exists()) {
            encryptedKeyFile.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(encryptedKeyFile);
        fos.write(encryptedKey);
        fos.close();
    }

    public static void decryptKey (String encKeyFilename,
                                   String decryptedKeyFilename,
                                   KeyStore keyStore,
                                   String certificateAlias) throws IOException, KeyStoreException, NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        File encKeyFile = new File(encKeyFilename);
        if(!encKeyFile.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream fis = new FileInputStream(encKeyFile);
        var encKey = fis.readAllBytes();

        //get priv key from ks
        PrivateKey privKey = (PrivateKey) keyStore.getKey("marakey", "marapass".toCharArray());
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        var decrypted = cipher.doFinal(encKey);

        File output = new File(decryptedKeyFilename);
        if (!output.exists()){
            output.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(decrypted);
    }

    public static void encryptWithPrivate(String keyFilename,
                                          String encryptedKeyFilename,
                                          KeyStore keyStore,
                                          String certificateAlias) throws IOException, KeyStoreException, NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        File encKeyFile = new File(keyFilename);
        if(!encKeyFile.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream fis = new FileInputStream(encKeyFile);
        var encKey = fis.readAllBytes();

        //get priv key from ks
        PrivateKey privKey = (PrivateKey) keyStore.getKey("marakey", "marapass".toCharArray());
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        var decrypted = cipher.doFinal(encKey);

        File output = new File(encryptedKeyFilename);
        if (!output.exists()){
            output.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(decrypted);
    }

    public static void decryptWithPublic(String keyFilename,
    String encryptedFeyFilename,
    KeyStore keyStore,
    String certificateAlias) throws KeyStoreException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        //get prof public key from keystore
        PublicKey publicKey = keyStore.getCertificate(certificateAlias).getPublicKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        //encrypt
        File keyFile = new File(keyFilename);
        if (!keyFile.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream fis = new FileInputStream(keyFile);
        var aes_key = fis.readAllBytes();
        var decryptedKey = cipher.doFinal(aes_key);
        fis.close();

        //write to file
        File encryptedKeyFile = new File(encryptedFeyFilename);
        if (!encryptedKeyFile.exists()) {
            encryptedKeyFile.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(encryptedKeyFile);
        fos.write(decryptedKey);
        fos.close();
    }
}
