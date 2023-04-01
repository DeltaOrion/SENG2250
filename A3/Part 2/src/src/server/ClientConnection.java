package src.server;

import src.ClientServerConnection;

import java.io.IOException;
import java.net.Socket;

/**
 * Represents a connection between the client and the server, clientbound from the server.
 */
public class ClientConnection extends ClientServerConnection {

    private final SecureServer server;

    public ClientConnection(Socket socket, SecureServer server) throws IOException {
        super(socket);
        this.server = server;
    }

    @Override
    public void logMessage(String message) {
        System.out.println("[Server] "+message);
    }
}
