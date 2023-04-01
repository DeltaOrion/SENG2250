package src.client;

import src.ClientServerConnection;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Represents a connection from the client bound to the server.
 */
public class ServerConnection extends ClientServerConnection {
    public ServerConnection(InetSocketAddress address) throws IOException {
        super(getSocket(address));
    }

    private static Socket getSocket(InetSocketAddress address) throws IOException {
        return new Socket(address.getHostName(),address.getPort());
    }

    @Override
    public void logMessage(String message) {
        System.out.println("[Client] "+message);
    }
}
