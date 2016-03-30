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
        String clientMessage;
        String capitalisedMessage;

        ServerSocket serverSocket = new ServerSocket(2222);

        System.out.println("The has server started. To stop it press <CTRL><C>.");

        Socket clientSocket = serverSocket.accept();

        BufferedReader inFromClient = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        PrintStream outToClient = new PrintStream(clientSocket.getOutputStream());

        while (true) {
            clientMessage = inFromClient.readLine();

            System.out.println("Received: " + clientMessage);

            capitalisedMessage = clientMessage.toUpperCase();
            outToClient.println(capitalisedMessage);
        }
    }
}
