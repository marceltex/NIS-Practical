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
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.digest.DigestUtils;
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
    private ByteArrayOutputStream byteArrayOutputStream = null;
    private final ClientThread[] threads;
    private int maxClientsCount;
    private static byte[] iv;
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
        byte[] encryptedSessionKey = new byte[128];
        byte[] abyte = new byte[1];
        iv = new byte[16];
        try {
            // Create input stream for this client.
            is = clientSocket.getInputStream();

            if (is != null) {
                System.out.println("Message Recieved! Starting verification...\n");
                is.read(iv, 0, 16);
                is.read(encryptedSessionKey, 0, 128);
                byte[] sessionKey = decryptSessionKey(privateKeyRing.get("server"), encryptedSessionKey);
                String sessionKeyString = new String(sessionKey, "UTF-8");
                System.out.println("1)  Session Key extracted and decrypted with server private key:\n" + sessionKeyString);
                byte[] decodedSessionKey = Base64.getDecoder().decode(sessionKeyString);
//                System.out.println("decrypted session key: " + new String(decodedSessionKey, "UTF-8"));

                byteArrayOutputStream = new ByteArrayOutputStream();
                int pos = 0;
                bytesRead = is.read(abyte, 0, abyte.length);
                do {
                    if (pos > 143) {
                        byteArrayOutputStream.write(abyte);
                        bytesRead = is.read(abyte);
                    }
                    pos++;
                } while (bytesRead != -1);
                byte[] message = byteArrayOutputStream.toByteArray();
                System.out.println("\n\n2)  Encrypted message extracted:\n" + new String(message, "UTF-8") + "\n");

                SecretKey secretSessionKey = new SecretKeySpec(decodedSessionKey, 0, decodedSessionKey.length, "AES");
                byte[] sessionMessage = null;
                try {
                    sessionMessage = decryptZipAES(secretSessionKey, message);
                    System.out.println("\n3)  Message decrypted using session key:\n" + new String(sessionMessage, "UTF-8"));
                } catch (Exception ex) {
                    Logger.getLogger(ClientThread.class.getName()).log(Level.SEVERE, null, ex);
                }

                byte[] uncompressedMessage = decompress(sessionMessage);
                System.out.println("\n\n4)  Message decompressed resulting in plaintext message and encrypted hash:\n" + new String(uncompressedMessage, "UTF-8"));

                byte[] encryptedHash = new byte[128];
                byte[] msg = new byte[uncompressedMessage.length - 128];
                for (int i = 0; i < 128; i++) {
                    encryptedHash[i] = uncompressedMessage[i];
                }
                //System.out.println(new String(encryptedHash, "UTF-8"));

                String decryptedHashFinal = decryptHash(publicKeyRing.get("client"), encryptedHash);
                System.out.println("\n\n5)  Hash decrypted using client public key:" + decryptedHashFinal);

                for (int i = 128; i < uncompressedMessage.length; i++) {
                    msg[i - 128] = uncompressedMessage[i];
                }

                String sha1Hash = DigestUtils.sha1Hex(new String(msg, "UTF-8"));
                System.out.println("6)  Hash of message calculated:    " + sha1Hash);
                System.out.println("\nDoes the message Hash equal the client sent hash?:  " + sha1Hash.equals(decryptedHashFinal));
                System.out.println("\n------------------------------------------------------------------------------------------------\n");
                System.out.println("Message Verified, the original message was: \n\"" + new String(msg, "UTF-8")+"\"\n\n");
System.out.println("---------------------------------------------------------------------------------------------------\n\nReady For New Connection!\n\n");
                synchronized (this) {
                    for (int i = 0; i < maxClientsCount; i++) {
                        if (threads[i] == this) {
                            threads[i] = null;
                        }
                    }
                }
            }
            is.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (DataFormatException ex) {
            Logger.getLogger(ClientThread.class.getName()).log(Level.SEVERE, null, ex);
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
            plainText = new String(cipherTextBytes, "UTF-8");
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
    private byte[] decryptSessionKey(String privateKey, byte[] encryptedSessionKey) {
        String plainText = null;

        Security.addProvider(new BouncyCastleProvider());
        byte[] cipherTextBytes = null;
        try {
            byte[] decodedKeyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey pubKey = keyFactory.generatePrivate(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cipher.init(cipher.DECRYPT_MODE, pubKey);

            cipherTextBytes = cipher.doFinal(encryptedSessionKey);
            //plainText = new String(cipherTextBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherTextBytes;
        //return plainText;
    }

    /**
     * Method used to decompress message and the message's signature. Adapted
     * from http://www.mkyong.com/java/how-to-decompress-files-from-a-zip-file/
     *
     * @param zipFilename Name of the compressed zip file
     * @param outputFolderName Name of the folder in which to store the
     * decompressed files
     */
    public byte[] decompress(byte[] data) throws DataFormatException, IOException {
        Inflater inflater = new Inflater();
        inflater.setInput(data);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[1024];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            outputStream.write(buffer, 0, count);
        }

        outputStream.close();
        byte[] output = outputStream.toByteArray();
        return output;

    }

    public byte[] decryptZipAES(SecretKey sessionKey, byte[] encrypted) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivParams);
        byte[] original = cipher.doFinal(encrypted);
        return original;
    }
}
