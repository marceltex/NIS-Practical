package nispractical;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import org.apache.commons.codec.digest.DigestUtils;

/**
 * A TCP Client that will transmit a message securely, using the PGP protocol.
 *
 * @author Marcel Teixeira
 * @version 0.4
 */
public class TCPClient {

    private static final String IP_ADDRESS = "localhost";
    private static final int PORT = 2222;

    private static final Map<String, String> publicKeyRing;

    static {
        publicKeyRing = new HashMap<String, String>();
        publicKeyRing.put("client", "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCWa0pDw5g/a0L3lEY3aprKmgDRu3cxbhlo97CNiLUwPohkgr9BJon0q6BzesdeLI8tmswgV09ZvkPXIhoiOGevsumXFEWp5IMCo7HnijfYZH0aMG3bnfxoKDo/5NNUIpPPdXEObDJNQ2heNmNoaasPsaqRLF3TqdtzAXr9e8343wIDAQAB");
        publicKeyRing.put("server", "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYBjV6H7fIfmOCQKDnd14B0lEH8j1Qe0xE5sDWzhAU/ZGJIT4c0M7tB5bwkxjIMFKpb5fGUYhOWAgDT+Oqg4MdmgzbeVxyK1hRXrhBOwjUQPNlN8z8Xr6qvi3PkhxvmfwlLUXdYroGaVuBvF7YYohYLpspwNPwDaZxUHkie8gaKwIDAQAB");
    }

    private static final Map<String, String> privateKeyRing;

    static {
        privateKeyRing = new HashMap<String, String>();
        privateKeyRing.put("client", "");
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        String message = "";
        String modifiedMessage;

        Socket clientSocket = null;
        PrintStream outToServer = null;
        BufferedReader inFromServer = null;

        // Open a socket on port 2222. Open the input and output streams
        try {
            System.out.println("The client has started.");
            clientSocket = new Socket(IP_ADDRESS, PORT);
            System.out.println("Successfully connected to server at IP Address: "
                    + IP_ADDRESS + " using Port Number: " + PORT);

            outToServer = new PrintStream(clientSocket.getOutputStream());
            inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        } catch (UnknownHostException e) {
            System.err.println("Can't find the host");
        } catch (IOException e) {
            System.err.println("Couldn't connect to server at IP Address: "
                    + IP_ADDRESS + " using Port Number: " + PORT);
        }

        // If statement ensures that everything has been initialised successfully
        if (clientSocket != null && outToServer != null && inFromServer != null) {
            try {
                Scanner read = new Scanner(new File("messages/message.txt"));

                while (read.hasNext()) {
                    message += read.nextLine();
                }

                System.out.println("Plain text message to be transmitted:\n\"" + message + "\"\n");

                System.out.println("**************************");
                System.out.println("* PGP Encryption Started *");
                System.out.println("**************************\n");

                String sha1Hash = DigestUtils.sha1Hex(message);

                System.out.println("1) SHA-1 Hash of the message: " + sha1Hash + "\n");

                outToServer.println(message);
                modifiedMessage = inFromServer.readLine();

                System.out.println("FROM SERVER: " + modifiedMessage);

                // Close output/input streams and socket
                outToServer.close();
                inFromServer.close();
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
}
