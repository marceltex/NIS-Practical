package nispractical;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;

/**
 * Client Thread class used to create Client Thread objects of the clients
 * connected to the server at any given instant.
 *
 * @author Marcel Teixeira
 * @version 0.1
 */
public class ClientThread extends Thread {

    private Socket clientSocket = null;
    private InputStream is = null;
    private FileOutputStream fileOutputStream = null;
    private BufferedOutputStream bufferedOutputStream = null;
    private ByteArrayOutputStream byteArrayOutputStream = null;
    private final ClientThread[] threads;
    private int maxClientsCount;

    private static final String FILENAME = "messages/message";

    private final Map<String, String> publicKeyRing;
    private final Map<String, String> privateKeyRing;

    public ClientThread(Socket clientSocket, ClientThread[] threads) {
        this.clientSocket = clientSocket;
        this.threads = threads;
        maxClientsCount = threads.length;

        publicKeyRing = new HashMap<String, String>();
        publicKeyRing.put("client", "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCWa0pDw5g/a0L3lEY3aprKmgDRu3cxbhlo97CNiLUwPohkgr9BJon0q6BzesdeLI8tmswgV09ZvkPXIhoiOGevsumXFEWp5IMCo7HnijfYZH0aMG3bnfxoKDo/5NNUIpPPdXEObDJNQ2heNmNoaasPsaqRLF3TqdtzAXr9e8343wIDAQAB");
        publicKeyRing.put("server", "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYBjV6H7fIfmOCQKDnd14B0lEH8j1Qe0xE5sDWzhAU/ZGJIT4c0M7tB5bwkxjIMFKpb5fGUYhOWAgDT+Oqg4MdmgzbeVxyK1hRXrhBOwjUQPNlN8z8Xr6qvi3PkhxvmfwlLUXdYroGaVuBvF7YYohYLpspwNPwDaZxUHkie8gaKwIDAQAB");

        privateKeyRing = new HashMap<String, String>();
        privateKeyRing.put("server", "MIICdAIBADANBgkqhkiG9w0BAQEFAASCAl4wggJaAgEAAoGBAJgGNXoft8h+Y4JAoOd3XgHSUQfyPVB7TETmwNbOEBT9kYkhPhzQzu0HlvCTGMgwUqlvl8ZRiE5YCANP46qDgx2aDNt5XHIrWFFeuEE7CNRA82U3zPxevqq+Lc+SHG+Z/CUtRd1iugZpW4G8XthiiFgumynA0/ANpnFQeSJ7yBorAgMBAAECfwkNng5VpOl3JJyJzaXK0cSvb4lW46ujrBKLVGlPtYh7+4Dc94PX8FQQRkieP/O1pIishtrn9msximpuHYr7fxbt5IQMtmxLKUY0NoxN5dYDGPBVQPm8nWDupADy11pKA8FsUb2psrcSQ9yoGvQmW7plncYhuXaAlPhsX4PySwECQQDMtyMTl60zU1xY1r/OoZhYk5jm/eDEbPT9Xk4PKf0W7/F+LSpPf/ZZtBBkMkSkg7NxSguKzvxMSXTdNMXo1zZbAkEAvhvewKp0tNyweZQ+cFKAlsyphfiAMk7SRY5dUehRly0JKgmW3AOOi94bh52TQpmz8D8KXNuZxQvcXLTqN74UcQJABfjx1Qh/zReJgi4Buo2MXEkyFMsjW5eyLhIqRNb8w0aMzRmUOm2JSmSudb3hsssE2TFH1Ozk/3TFLA72FyzwMQJBAIAI8Sq9IkC06T3Ys3yec/AcAogx5tT69O7XhM4nMtwn/qYLM0kWNCjK+6uIWqdeMSu6qVYEqDlnVZAyYBQOtmECQFBseqlqIXBxSDma0BDKcet2zc/IbC32Kz/g4aboV/KWX33jlDi/JUpD9IKVXyVagzBVj4iyCdTyI6RkAmiuVvw=");
    }

    public void run() {
        int maxClientsCount = this.maxClientsCount;
        ClientThread[] threads = this.threads;

        int bytesRead;
        byte[] abyte = new byte[1];

        try {
            // Create input stream for this client.
            is = clientSocket.getInputStream();

            if (is != null) {
                byteArrayOutputStream = new ByteArrayOutputStream();
                fileOutputStream = new FileOutputStream(FILENAME + ".zip");
                bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
                bytesRead = is.read(abyte, 0, abyte.length);

                do {
                    byteArrayOutputStream.write(abyte);
                    bytesRead = is.read(abyte);
                } while (bytesRead != -1);

                bufferedOutputStream.write(byteArrayOutputStream.toByteArray());
                bufferedOutputStream.flush();

                System.out.println("File message.zip received\n");

                System.out.println("Decompressing file...");

                System.out.println("message.zip decompressed successfully\n");

                synchronized (this) {
                    for (int i = 0; i < maxClientsCount; i++) {
                        if (threads[i] == this) {
                            threads[i] = null;
                        }
                    }
                }
            }
            // Close the input and output streams and close the socket
            bufferedOutputStream.close();
            fileOutputStream.close();
            is.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Method used to decrypt the hash of the message that was encrypted using
     * the RSA algorithm in ECB mode with PKCS1 padding.
     *
     * @param publicKey Client's public key used to encrypt the hash
     * @param encryptedHash Hash to be decrypted
     * @return Plain text version of hash (Decrypted hash)
     */
    private String decryptHash(String publicKey, byte[] encryptedHash) {
        String plainText = null;

        Security.addProvider(new BouncyCastleProvider());

        try {
            byte[] decodedKeyBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cipher.init(cipher.DECRYPT_MODE, pubKey);

            byte[] cipherTextBytes = cipher.doFinal(encryptedHash);
            plainText = new String(cipherTextBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return plainText;
    }

    /**
     * Method used to decrypt the session key of the message that was encrypted
     * using the RSA algorithm in ECB mode with PKCS1 padding.
     *
     * @param publicKey Client's public key used to encrypt the hash
     * @param encryptedHash Hash to be decrypted
     * @return Plain text version of hash (Decrypted hash)
     */
    private String decryptSessionKey(String privateKey, byte[] encryptedSessionKey) {
        String plainText = null;

        Security.addProvider(new BouncyCastleProvider());

        try {
            byte[] decodedKeyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey pubKey = keyFactory.generatePrivate(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cipher.init(cipher.DECRYPT_MODE, pubKey);

            byte[] cipherTextBytes = cipher.doFinal(encryptedSessionKey);
            plainText = new String(cipherTextBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return plainText;
    }

    /**
     * Method used to decompress message and the message's signature. Adapted
     * from http://www.mkyong.com/java/how-to-decompress-files-from-a-zip-file/
     *
     * @param zipFilename Name of the compressed zip file
     * @param outputFolderName Name of the folder in which to store the
     * decompressed files
     */
    public byte[] decompress(byte[] compressedByteArray) {         
        ByteArrayOutputStream baos = null;
        Inflater iflr = new Inflater();
        iflr.setInput(compressedByteArray);
        baos = new ByteArrayOutputStream();
        byte[] tmp = new byte[4*1024];
        try{
            while(!iflr.finished()){
                int size = iflr.inflate(tmp);
                baos.write(tmp, 0, size);
            }
        } catch (Exception ex){
             
        } finally {
            try{
                if(baos != null) baos.close();
            } catch(Exception ex){}
        }
        return baos.toByteArray();
    }

    public String decryptZipAES(SecretKey sessionKey, String encrypted) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] iv = new byte[cipher.getBlockSize()];
        randomSecureRandom.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivParams);
        byte[] decodedBytes = new BASE64Decoder().decodeBuffer(encrypted);
        byte[] original = cipher.doFinal(decodedBytes);
        String decryptedValue = new String(original);
        return decryptedValue;
    }
}
