package nispractical;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;

/**
 *
 * @author Marcel Teixeira
 */
public class TCPServer {

    /**
     * @param args the command line arguments
     * @throws Exception if there are connectivity issues
     */
    public static void main(String[] args) throws Exception {
        String clientSentence;
        String capitalisedSentence;
        
        ServerSocket welcomeSocket = new ServerSocket(6789);
        
        System.out.println("The server started. To stop it press <CTRL><C>.");

        while (true) {
            Socket connectionSocket = welcomeSocket.accept();
            BufferedReader inFromClient
                    = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
            PrintStream outToClient = new PrintStream(connectionSocket.getOutputStream());
            clientSentence = inFromClient.readLine();
            System.out.println("Received: " + clientSentence);
            capitalisedSentence = clientSentence.toUpperCase();
            outToClient.println(capitalisedSentence);
        }
    }
}
