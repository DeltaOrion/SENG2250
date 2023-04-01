package src.server.protocol;

import src.DataExchangeProtocol;
import src.Packet;
import src.Protocol;
import src.UnexpectedPacketException;
import src.crypto.AESCryptoSystem;
import src.crypto.DHE_RSA_SHA256;
import src.packets.*;
import src.server.ClientConnection;
import src.server.SecureServer;
import src.server.SecureSession;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Represents the actions that the server will take when executing the handshake protocol. The protocol
 * works as follows
 *
 * C -> S: Hello
 * S -> C: Server_Hello
 * C -> S: EDHKE Client
 * S -> C: EDHKE Server
 * C -> S: EDHKE Key Confirm Client
 * S -> C: EDHKE key Confirm Server
 */
public class ServerHandshakeProtocol extends Protocol {

    private final SecureServer server;
    private final ClientConnection connection;
    private SecureSession session;
    private Packet input;
    private PacketType state;

    public ServerHandshakeProtocol(SecureServer server, ClientConnection connection) {
        this.server = server;
        this.connection = connection;
        this.state = null;
    }

    @Override
    public void init() {
        //client should initiate handshake protocol
    }

    @Override
    public void setInput(Packet packet) {
        this.input = packet;
    }

    @Override
    public Protocol run() throws UnexpectedPacketException {
        switch (input.getType()) {
            case CLIENT_HANDSHAKE_HELLO:
                return handleHello((PacketClientHandshakeHello) input);
            case CLIENT_HANDSHAKE_RSA_DHE:
                return handleDHE((PacketClientHandshakeDHE) input);
            case CLIENT_HANDSHAKE_KEY_CONFIRM:
                return handleConfirm((PacketClientHandshakeKeyConfirm) input);
            default:
                throw new UnexpectedPacketException("Unknown packet for protocol");
        }
    }

    @Override
    public String getName() {
        return "Handshake";
    }

    private Protocol handleConfirm(PacketClientHandshakeKeyConfirm packet) throws UnexpectedPacketException {
        if(state!=PacketType.SERVER_HANDSHAKE_RSA_DHE)
            throw new UnexpectedPacketException();

        try {
            //--- Check that the client confirm is valid ---//
            byte[] expected = packet.getNonceServer().toByteArray();
            AESCryptoSystem cryptoSystem = session.getCryptoSystem();
            DHE_RSA_SHA256 dhe = session.getDHE();

            cryptoSystem.init(Cipher.DECRYPT_MODE);
            //decrypt the message sent by the client
            byte[] decrypted = cryptoSystem.ECB(packet.getCipherText());
            //check that the message is equal to the nonce we sent the client
            if(!Arrays.equals(decrypted, expected))
                throw new UnexpectedPacketException("Could not confirm client key possession, decrypted message not equal!");

            //--- Send own confirm message --//
            cryptoSystem.init(Cipher.ENCRYPT_MODE);
            //encrypt the clients nonce
            byte[] cipherText = cryptoSystem.ECB(packet.getNonceClient().toByteArray());
            //send the clients nonce encrypted with the key
            PacketServerHandshakeKeyConfirm confirmPacket = new PacketServerHandshakeKeyConfirm(packet.getNonceClient(),dhe.getNonce(),cipherText);
            state = PacketType.SERVER_HANDSHAKE_KEY_CONFIRM;
            connection.sendPacket(confirmPacket);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new UnexpectedPacketException();
        }

        return new DataExchangeProtocol(false,session);
    }

    private Protocol handleDHE(PacketClientHandshakeDHE packet) throws UnexpectedPacketException {
        if(state!=PacketType.SERVER_HANDSHAKE_HELLO)
            throw new UnexpectedPacketException();

        DHE_RSA_SHA256 dhe = session.getDHE();
        try {
            //-- Perform DHE --//
            //use the key sent by the client to generate the servers own public key for the session, this can also
            //be used to generate the shared key
            dhe.receiveGenerateShared(packet.getPublicKey(), DHE_RSA_SHA256.DEFAULT_KEY_LENGTH, DHE_RSA_SHA256.DEFAULT_AES_LENGTH);

            //set shared key for the cryptosystem so we can encrypt messages later
            session.getCryptoSystem().setKey(dhe.getSharedKey());
            session.getCryptoSystem().setKPrime(dhe.getkPrime());
            state = PacketType.SERVER_HANDSHAKE_RSA_DHE;

            //--Send own DHE packet --//
            //Forge a digital signature with all of the information
            BigInteger signature = server.getRSA().digitalSignature(dhe.getNonce().toByteArray(),dhe.getPublicKey().getY().toByteArray(),dhe.getPublicKey().getG().toByteArray());
            //send the public key over to the client so they can forge their own shared key
            PacketServerHandshakeDHE dhePacket = new PacketServerHandshakeDHE(dhe.getPublicKey(),dhe.getNonce(),signature);
            connection.sendPacket(dhePacket);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new UnexpectedPacketException(e);
        }

        return this;
    }

    private Protocol handleHello(PacketClientHandshakeHello packet) throws UnexpectedPacketException {
        if(state!=null)
            throw new UnexpectedPacketException();

        session = server.getOrMake(connection,packet.getClientId());
        //send server hello
        state = PacketType.SERVER_HANDSHAKE_HELLO;
        session.sendPacket(new PacketServerHandshakeHello(server.getServerId(), session.getSessionId()));
        return this;
    }


}
