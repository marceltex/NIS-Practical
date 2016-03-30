package nispractical;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import java.util.Scanner;

/**
 *
 * @author Marcel Teixeira
 */
public class TCPClient {

    public static final String IP_ADDRESS = "localhost";

    /**
     * @param args the command line arguments
     * @throws Exception if there are connectivity issues
     */
    public static void main(String[] args) throws Exception {
        String sentence;
        String modifiedSentence;

        Scanner inFromUser = new Scanner(System.in);

        Socket clientSocket = new Socket(IP_ADDRESS, 6789);

        DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
        BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

        do {
            System.out.println("Type your message below: (Type 'q' to stop client)");
            sentence = inFromUser.nextLine();

            outToServer.writeBytes(sentence + '\n');
            modifiedSentence = inFromServer.readLine();

            System.out.println("FROM SERVER: " + modifiedSentence);
        } while (!sentence.toLowerCase().equals("q"));

        // Close output/input streams and socket
        outToServer.close();
        inFromServer.close();
        clientSocket.close();
    }
}
