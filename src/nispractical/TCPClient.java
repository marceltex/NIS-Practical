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

    /**
     * @param args the command line arguments
     * @throws Exception if there are connectivity issues
     */
    public static void main(String[] args) throws Exception {
        String sentence;
        String modifiedSentence;
        Scanner inFromUser = new Scanner(System.in);
        Socket clientSocket = new Socket("localhost", 6789);
        DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
        BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        System.out.println("The client started. Please type your message below:");
        sentence = inFromUser.nextLine();
        outToServer.writeBytes(sentence + '\n');
        modifiedSentence = inFromServer.readLine();
        System.out.println("FROM SERVER: " + modifiedSentence);
        
        // Close output/input streams and socket
        outToServer.close();
        inFromServer.close();
        clientSocket.close();
    }
}
