package nispractical;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * A TCP Server that will decrypt a message that was encrypted by the client
 * using the PGP protocol.
 *
 * @author Marcel Teixeira
 * @version 0.4
 */
public class TCPServer {

    public static final int PORT = 2222;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        String clientMessage;
        String capitalisedMessage;

        ServerSocket serverSocket = null;
        BufferedReader inFromClient = null;
        PrintStream outToClient = null;
        Socket clientSocket = null;

        // Open a server socket on port 2222
        try {
            serverSocket = new ServerSocket(PORT);
            System.out.println("The server has started using Port Number: "
                    + PORT + ". To stop it press <CTRL><C>.");
        } catch (IOException e) {
            System.err.println("Failed to start the server on Port Number: "
                    + PORT + ". Error message produced: " + e);
        }

        // Create a socket object from the ServerSocket to listen to and accept
        // connections. Open input and output streams.
        try {
            clientSocket = serverSocket.accept();

            inFromClient = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            outToClient = new PrintStream(clientSocket.getOutputStream());

            while (true) {
                clientMessage = inFromClient.readLine();

                if (clientMessage != null) {
                    System.out.println("Received: " + clientMessage);

                    capitalisedMessage = clientMessage.toUpperCase();
                    outToClient.println(capitalisedMessage);
                }
            }
        } catch (IOException e) {
            System.err.println(e);
        }
    }
}
