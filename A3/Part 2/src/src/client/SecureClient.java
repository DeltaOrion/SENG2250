package src.client;

import src.SecureEntity;
import src.client.protocol.ClientSetupProtocol;
import src.util.IdGenerator;
import src.Packet;
import src.crypto.AESCryptoSystem;
import src.crypto.DHE_RSA_SHA256;
import src.crypto.RSA;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.spec.RSAPublicKeySpec;

/**
 * Represents the client as an entity that can send messages to the server. This provides an abstraction over the sockets
 * layer. This contains all of the information about the client and is independent of any connection. This represents session
 * information and long-term information about the client.
 */
public class SecureClient implements Runnable, SecureEntity {

    //the current connection between the client and the server
    private ServerConnection connection;
    private final InetSocketAddress serverAddress;

    //security information for THIS SESSION
    private final RSA rsa;
    private final DHE_RSA_SHA256 dhe;
    private final AESCryptoSystem cryptoSystem;

    //ids
    private final int clientId;
    private int sessionId;

    public SecureClient(InetSocketAddress serverAddress) {
        this.serverAddress = serverAddress;
        this.rsa = new RSA();
        this.dhe = new DHE_RSA_SHA256();
        this.clientId = IdGenerator.getInstance().generateId();

        try {
            this.cryptoSystem = new AESCryptoSystem();
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void run() {
        try {
            //connect to the server
            System.out.println("Client -> Connecting");
            connection = new ServerConnection(serverAddress);
        } catch (IOException e) {
            System.err.println("An error occurred while connecting to the server address");
        }

        //initializes the connection with the setup protocol
        connection.init(new ClientSetupProtocol(this));
        //start listening for packets
        connection.run();
    }

    @Override
    public void sendPacket(Packet packet) {
        connection.sendPacket(packet);
    }

    @Override
    public void logMessage(String message) {
        connection.logMessage(message);
    }

    public void setServerKeys(RSAPublicKeySpec publicKey) {
        rsa.setKeys(publicKey);
    }

    public int getSessionId() {
        return sessionId;
    }

    public void setSessionId(int sessionId) {
        this.sessionId = sessionId;
    }

    public int getClientId() {
        return clientId;
    }

    @Override
    public DHE_RSA_SHA256 getDHE() {
        return dhe;
    }

    public void setConnection(ServerConnection connection) {
        this.connection = connection;
    }

    @Override
    public RSA getRSA() {
        return rsa;
    }

    @Override
    public AESCryptoSystem getCryptoSystem() {
        return cryptoSystem;
    }
}
