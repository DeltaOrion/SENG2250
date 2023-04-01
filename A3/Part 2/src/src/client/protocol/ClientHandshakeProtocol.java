package src.client.protocol;

import src.DataExchangeProtocol;
import src.Packet;
import src.Protocol;
import src.UnexpectedPacketException;
import src.client.SecureClient;
import src.crypto.AESCryptoSystem;
import src.crypto.DHE_RSA_SHA256;
import src.crypto.RSA;
import src.packets.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Represents the actions that the client will take when executing the handshake protocol. The protocol
 * works as follows
 *
 * C -> S: Hello
 * S -> C: Server_Hello
 * C -> S: EDHKE Client
 * S -> C: EDHKE Server
 * C -> S: EDHKE Key Confirm Client
 * S -> C: EDHKE key Confirm Server
 */
public class ClientHandshakeProtocol extends Protocol {

    private final SecureClient client;
    private Packet input;
    private PacketType state;
    private int serverId;

    public ClientHandshakeProtocol(SecureClient client) {
        this.client = client;
        this.state = null;
    }

    @Override
    public void init() {
        //start by sending the handshake hello to the server
        client.sendPacket(new PacketClientHandshakeHello(client.getClientId()));
        state = PacketType.CLIENT_HANDSHAKE_HELLO;
    }

    @Override
    public void setInput(Packet packet) {
        this.input = packet;
    }

    @Override
    public Protocol run() throws UnexpectedPacketException {
        switch (input.getType()) {
            case SERVER_HANDSHAKE_HELLO:
                return handleHello((PacketServerHandshakeHello) input);
            case SERVER_HANDSHAKE_RSA_DHE:
                return handleDHE((PacketServerHandshakeDHE) input);
            case SERVER_HANDSHAKE_KEY_CONFIRM:
                return handleConfirm((PacketServerHandshakeKeyConfirm) input);
            default:
                throw new UnexpectedPacketException();
        }
    }

    @Override
    public String getName() {
        return "Handshake";
    }

    private Protocol handleConfirm(PacketServerHandshakeKeyConfirm packet) throws UnexpectedPacketException {
        if(!state.equals(PacketType.CLIENT_HANDSHAKE_KEY_CONFIRM))
            throw new UnexpectedPacketException();

        //the server encrypted the nonce that the client sent to it.
        //check that the encrypted message is actually the nonce that was sent
        byte[] expected = packet.getNonceClient().toByteArray();
        AESCryptoSystem cryptoSystem = client.getCryptoSystem();
        try {
            //decrypt the nonce using ECB (nonce is 128 bits anyway so it is not relevant what we use)
            cryptoSystem.init(Cipher.DECRYPT_MODE);
            byte[] decrypted = cryptoSystem.ECB(packet.getCipherText());
            if(!Arrays.equals(decrypted, expected))
                throw new UnexpectedPacketException("Could not confirm server key possession, decrypted message not equal!");
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new UnexpectedPacketException();
        }

        //this protocol is now over, enter data exchange
        return new DataExchangeProtocol(true,client);
    }

    private Protocol handleDHE(PacketServerHandshakeDHE packet) throws UnexpectedPacketException {
        if (!state.equals(PacketType.CLIENT_HANDSHAKE_RSA_DHE))
            throw new UnexpectedPacketException();

        try {
            RSA rsa = client.getRSA();
            DHE_RSA_SHA256 dhe = client.getDHE();

            //--- Digital Signature Verification --//
            //prevent MITM attack
            //the signature sent by the server contains the nonce, public key, and generator
            //check that the signature matches the contents stored
            BigInteger signature = packet.getDigitalSignature();
            if (!rsa.verifySignature(signature,
                    packet.getNonce().toByteArray(),
                    packet.getPublicKey().getY().toByteArray(),
                    packet.getPublicKey().getG().toByteArray()
            )) {
                //if the signature cannot be verified then terminate the connection
                throw new UnexpectedPacketException("Digital Signature could not be verified!");
            }

            //-- Perform Diffie Hellman Ephemeral --//
            //generate the shared key using the public key given
            dhe.generateSharedKey(packet.getPublicKey(), DHE_RSA_SHA256.DEFAULT_AES_LENGTH);
            //we now have the shared key, set these for the cryptosystem so we can encrypt stuff later
            client.getCryptoSystem().setKey(dhe.getSharedKey());
            client.getCryptoSystem().setKPrime(dhe.getkPrime());

            //-- Send Key Confirm packet --//
            state = PacketType.CLIENT_HANDSHAKE_KEY_CONFIRM;
            AESCryptoSystem cryptoSystem = client.getCryptoSystem();
            cryptoSystem.init(Cipher.ENCRYPT_MODE);
            //encrypt the nonce sent by the server using the shared key
            byte[] cipherText = cryptoSystem.ECB(packet.getNonce().toByteArray());
            //send the ciphertext, the server nonce, our nonce to the server.
            PacketClientHandshakeKeyConfirm confirm = new PacketClientHandshakeKeyConfirm(packet.getNonce(),dhe.getNonce(),cipherText);
            client.sendPacket(confirm);
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new UnexpectedPacketException(e);
        }
        return this;
    }

    private Protocol handleHello(PacketServerHandshakeHello packet) throws UnexpectedPacketException {
        if (!state.equals(PacketType.CLIENT_HANDSHAKE_HELLO))
            throw new UnexpectedPacketException();

        //take the session id and server id from the packet
        client.setSessionId(packet.getSessionId());
        this.serverId = packet.getServerId();

        //Start the DHE
        DHE_RSA_SHA256 dhe = client.getDHE();
        state = PacketType.CLIENT_HANDSHAKE_RSA_DHE;
        //send the public key to the server.
        //generate our public key for this SESSION for the server.
        dhe.generatePublicKey(DHE_RSA_SHA256.DEFAULT_KEY_LENGTH);
        client.sendPacket(new PacketClientHandshakeDHE(dhe.getPublicKey()));
        return this;
    }

}
