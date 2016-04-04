package nispractical;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * A TCP Client that will transmit a message securely, using the PGP protocol.
 *
 * @author Marcel Teixeira
 * @version 0.4
 */
public class TCPClient {

    private static final String IP_ADDRESS = "localhost";
    private static final int PORT = 2222;

    private static final String FILENAME = "messages/message";

    private static final Map<String, String> publicKeyRing;

    static {
        publicKeyRing = new HashMap<String, String>();
        publicKeyRing.put("client", "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCWa0pDw5g/a0L3lEY3aprKmgDRu3cxbhlo97CNiLUwPohkgr9BJon0q6BzesdeLI8tmswgV09ZvkPXIhoiOGevsumXFEWp5IMCo7HnijfYZH0aMG3bnfxoKDo/5NNUIpPPdXEObDJNQ2heNmNoaasPsaqRLF3TqdtzAXr9e8343wIDAQAB");
        publicKeyRing.put("server", "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYBjV6H7fIfmOCQKDnd14B0lEH8j1Qe0xE5sDWzhAU/ZGJIT4c0M7tB5bwkxjIMFKpb5fGUYhOWAgDT+Oqg4MdmgzbeVxyK1hRXrhBOwjUQPNlN8z8Xr6qvi3PkhxvmfwlLUXdYroGaVuBvF7YYohYLpspwNPwDaZxUHkie8gaKwIDAQAB");
    }

    private static final Map<String, String> privateKeyRing;

    static {
        privateKeyRing = new HashMap<String, String>();
        privateKeyRing.put("client", "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJZrSkPDmD9rQveURjdqmsqaANG7dzFuGWj3sI2ItTA+iGSCv0EmifSroHN6x14sjy2azCBXT1m+Q9ciGiI4Z6+y6ZcURankgwKjseeKN9hkfRowbdud/GgoOj/k01Qik891cQ5sMk1DaF42Y2hpqw+xqpEsXdOp23MBev17zfjfAgMBAAECgYAL7Ujvs5gkWzBtqiOhLEJG00xCVQ9/6193a8BjkJXxU9wDwDxDAbfJnzwzO+aICJd3wcDyxYmEr6n4antRAFD0RdEmbdtq9z5uPoRrUoN/+vnTlovuwxEiecusk2kyho02IiYLRule6YQIeoU4sSYZGBwTrZiHHFiK5leQOKzG+QJBANPKmBd0c6PZv0+eadvkGlHct/2FvKbfWUkSSN7TvYbh8a3BcwgOTjF81ldmdL9RGQY/5LjqR4suOOWX18kEuYcCQQC10SvqeVV0DG6PYcEtBJ/5Q9zfTghnBYhPi1x6ceI9nResCkfqZvRo8o0XI50Q2vlLhBqx9QcD0f2LbDJGCTvpAkAKBkbYpVxr3vydKiRckhlk0ouq5k+dnmi9eq4UTfVkkwE7djKZqQOud/g1PtY7z/zdPNz4m64zOkbbJyrBiwW1AkEAhnuISy+iCGtln8KDm2PPXBVZGwbh6inKcGO5bIwt9rrqloMoPHYYlEPMHnBmLeB6AuRcxoJhxO6e5nCKIwmTeQJAdGj3KB4GfiqccBI2VKA4xYZ6Z4T9TFnxyglyPOYP9iq0GiEjUmj59Q3M4vuGuifBCzTprxTPBea9IIycnrHSHg==");
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        String message = "";
        String modifiedMessage;

        Socket clientSocket = null;
        PrintStream outToServer = null;
        BufferedReader inFromServer = null;
        FileInputStream fileInputStream = null;
        FileOutputStream fileOutputStream = null;
        FileOutputStream fos = null;
        BufferedInputStream bufferedInputStream = null;
        OutputStream os = null;

        // Open a socket on port 2222. Open the input and output streams
        try {
            System.out.println("The client has started.");
            clientSocket = new Socket(IP_ADDRESS, PORT);
            System.out.println("Successfully connected to server at IP Address: "
                    + IP_ADDRESS + " using Port Number: " + PORT);

            outToServer = new PrintStream(clientSocket.getOutputStream());
            inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            os = clientSocket.getOutputStream();
        } catch (UnknownHostException e) {
            System.err.println("Can't find the host");
        } catch (IOException e) {
            System.err.println("Couldn't connect to server at IP Address: "
                    + IP_ADDRESS + " using Port Number: " + PORT);
        }

        // If statement ensures that everything has been initialised successfully
        if (clientSocket != null && outToServer != null && inFromServer != null) {
            try {
                Scanner read = new Scanner(new File(FILENAME + ".txt"));
                fileOutputStream = new FileOutputStream(FILENAME + ".sig");
                fos = new FileOutputStream("hi.sig");
                List<File> files = new ArrayList<File>();

                while (read.hasNext()) {
                    message += read.nextLine();
                }

                System.out.println("Plain text message to be transmitted:\n\"" + message + "\"\n");

                System.out.println("**************************");
                System.out.println("* PGP Encryption Started *");
                System.out.println("**************************\n");

                String sha1Hash = DigestUtils.sha1Hex(message);

                System.out.println("1) SHA-1 hash of the message: " + sha1Hash + "\n");

                byte[] encryptedHash = encryptHash(privateKeyRing.get("client"), sha1Hash);

                byte[] messageAndHash = combineByteArrs(message.getBytes(),0,encryptedHash,128);
                
                System.out.println("2) Encrypted SHA-1 hash:");
                System.out.println(new String(encryptedHash, "UTF-8") + "\n");

                fileOutputStream.write(encryptedHash);

                fileOutputStream.close();

                files.add(new File(FILENAME + ".txt"));
                files.add(new File(FILENAME + ".sig"));

                File compressedFile = compress(files, FILENAME + ".zip");

                System.out.println("3) Message and message signature compressed "
                        + "to '" + compressedFile.getName() + "' successfully\n");

                SecretKey sessionKey = generateAESSessionKey();
                System.out.println("4) Session key and IV generated\n");
                byte[] buffer = new byte[(int) compressedFile.length()];

                fileInputStream = new FileInputStream(compressedFile);
                bufferedInputStream = new BufferedInputStream(fileInputStream);
                bufferedInputStream.read(buffer, 0, buffer.length);
                byte[] encrypted = encryptZipAES(sessionKey, buffer);
                String encryptedValue = new BASE64Encoder().encode(encrypted);
                System.out.println("5) Compressed file encrypted:\n" + encryptedValue + "\n");

                String sessionKeyString = Base64.getEncoder().encodeToString(sessionKey.getEncoded());

                byte[] encryptedSessionKey = encryptSessionKey(publicKeyRing.get("server"), sessionKeyString);

                System.out.println("6) Session key encrypted using the server's "
                        + "public key:\n" + new String(encryptedSessionKey, "UTF-8") + "\n");

                byte[] finalMessage = combineByteArrs(encrypted,0,encryptedSessionKey,128);
                System.out.println("\n\n final Message:\n"+new String(finalMessage, "UTF-8"));
                fos.write(encryptedSessionKey);
                fos.close();

                System.out.println("Sending " + compressedFile.getName() + " (" + buffer.length + " bytes)\n");
                os.write(buffer, 0, buffer.length);
                os.flush();
                System.out.println("File sent to server successfully");
                os.close();

                // Close output/input streams and socket
                outToServer.close();
                inFromServer.close();
                fileInputStream.close();
                fileOutputStream.close();
                bufferedInputStream.close();
                clientSocket.close();
            } catch (FileNotFoundException e) {
                System.err.println("'message.txt' not found in messages directory");
                e.printStackTrace();
            } catch (UnknownHostException e) {
                System.err.println("Trying to connect to unknown host");
                e.printStackTrace();
            } catch (IOException e) {
                System.err.println("IOException");
                e.printStackTrace();
            }
        }
    }

    /**
     * Method used to encrypt the hash of the message using the RSA algorithm in
     * ECB mode with PKCS1 padding.
     *
     * @param privateKey Client's private key used to encrypt the hash
     * @param hash Hash to be encrypted
     * @return Byte array of RSA encrypted hash
     */
    private static byte[] encryptHash(String privateKey, String hash) {
        byte[] cipherText = null;

        Security.addProvider(new BouncyCastleProvider());

        try {
            byte[] decodedKeyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privKey = keyFactory.generatePrivate(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cipher.init(cipher.ENCRYPT_MODE, privKey);

            cipherText = cipher.doFinal(hash.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    /**
     * Method used to encrypt the session key using the RSA algorithm in ECB
     * mode with PKCS1 padding.
     *
     * @param privateKey Client's private key used to encrypt the hash
     * @param hash Hash to be encrypted
     * @return Byte array of RSA encrypted hash
     */
    private static byte[] encryptSessionKey(String publicKey, String sessionKey) {
        byte[] cipherText = null;

        Security.addProvider(new BouncyCastleProvider());

        try {
            byte[] decodedKeyBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey privKey = keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cipher.init(cipher.ENCRYPT_MODE, privKey);

            cipherText = cipher.doFinal(sessionKey.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    /**
     * Method used to compress message and the message's signature. Adapted from
     * http://stackoverflow.com/questions/16546992/how-to-create-a-zip-file-of-multiple-image-files
     *
     * @param files List of files to be compressed
     * @param filename Name of the zip file to store the compressed files
     * @return Zip file storing the compressed files
     */
    public static File compress(List<File> files, String filename) {
        File zipFile = new File(filename);

        // Buffer required to read files
        byte[] buffer = new byte[1024];
        try {
            ZipOutputStream zipOutputStream = new ZipOutputStream(new FileOutputStream(zipFile));
            // Compress the files
            for (int i = 0; i < files.size(); i++) {
                FileInputStream fileInputStream = new FileInputStream("messages/" + files.get(i).getName());

                zipOutputStream.putNextEntry(new ZipEntry(files.get(i).getName()));

                int length;
                while ((length = fileInputStream.read(buffer)) > 0) {
                    zipOutputStream.write(buffer, 0, length);
                }
                zipOutputStream.closeEntry();
                fileInputStream.close();
            }
            zipOutputStream.close();
            return zipFile;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static SecretKey generateAESSessionKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException n) {
            return null;
        }
    }

    public static byte[] encryptZipAES(SecretKey sessionKey, byte[] buffer) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] iv = new byte[cipher.getBlockSize()];
        randomSecureRandom.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivParams);
        byte[] encrypted = cipher.doFinal(buffer);
        return encrypted;
    }

    public static byte[] combineByteArrs(byte[] src,int srcpos, byte[] dest,int dstpos) {
        byte[] temp = new byte[src.length + dest.length];
        System.out.println(temp.length);
        System.arraycopy(dest, 0, temp, 0, dstpos);
        System.arraycopy(src, srcpos, temp, dstpos, src.length);
        return temp;
    }

}
