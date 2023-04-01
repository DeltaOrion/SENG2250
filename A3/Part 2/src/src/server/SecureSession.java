package src.server;

import src.SecureEntity;
import src.crypto.RSA;
import src.util.IdGenerator;
import src.Packet;
import src.crypto.AESCryptoSystem;
import src.crypto.DHE_RSA_SHA256;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

/**
 * Represents a client connected to the server. This includes all the stateful information
 * about the client. The connection and sockets layer is abstracted away in {@link ClientConnection}
 */
public class SecureSession implements SecureEntity {
    //identifying information
    private final int clientId;
    private final int sessionId;

    //the connection currently being used if any, a session lasts across multiple connections
    private ClientConnection connection;

    //security related informaiton
    private final DHE_RSA_SHA256 dhe;
    private final AESCryptoSystem cryptosystem;
    private final SecureServer server;

    public SecureSession(ClientConnection connection, int clientId, SecureServer server) {
        this.clientId = clientId;
        this.server = server;
        this.sessionId = IdGenerator.getInstance().generateId();
        this.connection = connection;
        this.dhe = new DHE_RSA_SHA256();
        try {
            this.cryptosystem = new AESCryptoSystem();
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException();
        }
    }

    public int getClientId() {
        return clientId;
    }

    public int getSessionId() {
        return sessionId;
    }

    public void setConnection(ClientConnection connection) {
        this.connection = connection;
    }

    public void sendPacket(Packet packet) {
        //a session can go across multiple connections so if there is no connection
        //as of now do nothing
        if(connection==null || connection.isClosed())
            return;

        connection.sendPacket(packet);
    }

    @Override
    public void logMessage(String message) {
        connection.logMessage(message);
    }

    @Override
    public DHE_RSA_SHA256 getDHE() {
        return dhe;
    }

    @Override
    public RSA getRSA() {
        return server.getRSA();
    }

    @Override
    public AESCryptoSystem getCryptoSystem() {
        return cryptosystem;
    }
}
