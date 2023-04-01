package src.server;

import src.server.protocol.ServerSetupProtocol;
import src.util.IdGenerator;
import src.crypto.RSA;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Represents the server. Once a client connects to the server it will
 * create a new {@link ClientConnection} which represents a connection betwene the server and the client. Once
 * the identity of the connection is established a {@link SecureSession} is created which represents a client
 * connected to the server with the sockets layer abstracted away. The SecureSession contains all the stateful
 * information about a client.
 *
 * Currently the server only supports one client but this could be easily modified by running each client from a cached thread pool
 */
public class SecureServer implements Runnable {
    private final InetSocketAddress address;
    private final RSA rsa;
    private ClientConnection connection;
    private SecureSession session;
    private final int uniqueId;
    private ServerSocket serverSocket;

    private final static int RSA_KEY_LENGTH = 2048;

    public SecureServer(InetSocketAddress address) {
        this.address = address;
        rsa = new RSA();
        rsa.generateKeys(RSA_KEY_LENGTH);
        this.uniqueId = IdGenerator.getInstance().generateId();
    }

    @Override
    public void run() {
        try {
            //start the server on the current port
            start(address.getPort());
        } catch (IOException e) {
            System.err.println("An error occurred while starting the connection");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } finally {
            //if any error occurs just stop the server, in a more sophisticated implementation
            //we would log the error and generate a crash report
            try {
                disconnect();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void start(int port) throws IOException, ClassNotFoundException {
        System.out.println("[Server] Listening for connections at port "+port);
        serverSocket = new ServerSocket(port);
        //listen for a connection
        Socket clientSocket = serverSocket.accept();
        //in a multi-client server we would start the connection in a new thread, i.e. using a cached thread pool
        connection = new ClientConnection(clientSocket,this);
        connection.init(new ServerSetupProtocol(connection,this));
        connection.run();
    }

    public void disconnect() throws IOException {
        //stops the server
        serverSocket.close();
        connection.disconnect();
    }

    public RSA getRSA() {
        return rsa;
    }

    public SecureSession getOrMake(ClientConnection connection, int clientId) {
        //create a session from the connection once the identity of the client
        //has been identified, in a multiclient environment we would have a list
        //of all of the sessions and grab the correct one
        session = new SecureSession(connection, clientId, this);
        return session;
    }

    public int getServerId() {
        return uniqueId;
    }
}
