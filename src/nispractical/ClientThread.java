package nispractical;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Socket;

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

    public ClientThread(Socket clientSocket, ClientThread[] threads) {
        this.clientSocket = clientSocket;
        this.threads = threads;
        maxClientsCount = threads.length;
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
                    for (int i = 0; i < maxClientsCount; i++) {
                        if (threads[i] == this) {
                            threads[i] = null;
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
}
