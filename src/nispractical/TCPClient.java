package nispractical;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
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
        String message;
        String modifiedMessage;

        Socket clientSocket = new Socket(IP_ADDRESS, 2222);

        PrintStream outToServer = new PrintStream(clientSocket.getOutputStream());
        BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

        Scanner inFromUser = new Scanner(System.in);

        System.out.println("Type your message below: (Type 'q' to stop client)");
        message = inFromUser.nextLine();

        outToServer.println(message);

        while ((modifiedMessage = inFromServer.readLine()) != null) {
            System.out.println("FROM SERVER: " + modifiedMessage);
            if (modifiedMessage.equals("Q")) {
                break;
            }
            System.out.println("Type your message below: (Type 'q' to stop client)");
            message = inFromUser.nextLine();

            outToServer.println(message);
        }

        // Close output/input streams and socket
        outToServer.close();
        inFromServer.close();
        clientSocket.close();
    }
}
