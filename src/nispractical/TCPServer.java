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

    private static final int PORT = 2222;

    private static ServerSocket serverSocket = null;
    private static Socket clientSocket = null;

    private static final int maxClientsCount = 10;
    private static final ClientThread[] threads = new ClientThread[maxClientsCount];

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        String clientMessage;
        String capitalisedMessage;

//        BufferedReader inFromClient = null;
//        PrintStream outToClient = null;

        // Open a server socket on port 2222
        try {
            serverSocket = new ServerSocket(PORT);
            System.out.println("The server has started using Port Number: "
                    + PORT + ". To stop it press <CTRL><C>.");
        } catch (IOException e) {
            System.err.println("Failed to start the server on Port Number: "
                    + PORT + ". Error message produced: " + e);
        }

        // Create a socket for each connection and pass it to a new client thread
        while (true) {
            try {
                clientSocket = serverSocket.accept();
                int i = 0;
                for (i = 0; i < maxClientsCount; i++) {
                    if (threads[i] == null) {
                        (threads[i] = new ClientThread(clientSocket, threads)).start();
                        break;
                    }
                }
                if (i == maxClientsCount) {
                    PrintStream outToClient = new PrintStream(clientSocket.getOutputStream());
                    outToClient.println("Server is too busy. Tr again later.");
                    outToClient.close();
                }
                
//                inFromClient = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
//                outToClient = new PrintStream(clientSocket.getOutputStream());
//
//                while (true) {
//                    clientMessage = inFromClient.readLine();
//
//                    if (clientMessage != null) {
//                        System.out.println("Received: " + clientMessage);
//
//                        capitalisedMessage = clientMessage.toUpperCase();
//                        outToClient.println(capitalisedMessage);
//                    }
//                }
            } catch (IOException e) {
                System.err.println(e);
            }
        }
    }
}
