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
    
    public static final int PORT = 2222;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        String clientMessage;
        String capitalisedMessage;

        ServerSocket serverSocket = new ServerSocket(PORT);

        System.out.println("The server has started. To stop it press <CTRL><C>.");

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
