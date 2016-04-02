package nispractical;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

/**
 * Client Thread class used to create Client Thread objects of the clients
 * connected to the server at any given instant.
 *
 * @author Marcel Teixeira
 * @version 0.1
 */
public class ClientThread extends Thread {

    private BufferedReader inFromClient = null;
    private PrintStream outToClient = null;
    private Socket clientSocket = null;
    private final ClientThread[] threads;
    private int maxClientsCount;

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
        String clientMessage;
        String capitalisedMessage;

        int maxClientsCount = this.maxClientsCount;
        ClientThread[] threads = this.threads;

        try {
            // Create input and output streams for this client.
            inFromClient = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            outToClient = new PrintStream(clientSocket.getOutputStream());

            while (true) {
                clientMessage = inFromClient.readLine();

                // Client up. Set the current thread variable to null so that a
                // new client can be accepted by the server.
                if (clientMessage == null) {
                    synchronized (this) {
                        for (int i = 0; i < maxClientsCount; i++) {
                            if (threads[i] == this) {
                                threads[i] = null;
                            }
                        }
                    }
                    break;
                }
                System.out.println("Received: " + clientMessage);

                capitalisedMessage = clientMessage.toUpperCase();
                outToClient.println(capitalisedMessage);
            }

            // Close the input and output streams and close the socket
            inFromClient.close();
            outToClient.close();
            clientSocket.close();
        } catch (IOException e) {
            System.err.println(e);
        }
    }
    
    /**
     * Method used to decrypt the hash of the message using the RSA algorithm in
     * ECB mode with PKCS1 padding.
     * 
     * @param publicKey Client's private key required to decrypt the hash
     * @param encryptedHash Encrypted hash to be decrypted
     * @return Decrypted hash (Plain text hash)
     */
    private String decryptHash(String publicKey, String encryptedHash) {
        return "";
    }
}
