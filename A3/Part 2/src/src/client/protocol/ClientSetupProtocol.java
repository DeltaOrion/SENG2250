package src.client.protocol;

import src.Packet;
import src.Protocol;
import src.UnexpectedPacketException;
import src.client.SecureClient;
import src.packets.PacketClientSetupHello;
import src.packets.PacketServerSetupRSAKey;
import src.packets.PacketType;

/**
 * Represents the actions that the client will take when executing the Setup protocol. The setup protocol
 * works as follows
 *
 * C -> S: Hello Setup Request
 * S -> C: RSA Public Key
 */
public class ClientSetupProtocol extends Protocol {

    private PacketType state;
    private Packet input;
    private SecureClient client;

    public ClientSetupProtocol(SecureClient client) {
        state = null;
        input = null;
        this.client = client;
    }

    @Override
    public void init() {
        //start by sending the server the setup hello packet
        state = PacketType.CLIENT_SETUP_HELLO;
        client.sendPacket(new PacketClientSetupHello("Hello!"));
    }

    @Override
    public void setInput(Packet packet) {
        input = packet;
    }

    @Override
    public Protocol run() throws UnexpectedPacketException {
        switch (input.getType()) {
            case SERVER_SETUP_RSA:
                return handleServerSetup((PacketServerSetupRSAKey) input);
            default:
                throw new UnexpectedPacketException();
        }
    }

    @Override
    public String getName() {
        return "Setup";
    }

    private Protocol handleServerSetup(PacketServerSetupRSAKey input) throws UnexpectedPacketException {
        if(!state.equals(PacketType.CLIENT_SETUP_HELLO))
            throw new UnexpectedPacketException();

        //assume that the key has been sent securely from the server
        //no extra checks like the X509 certificate is needed

        //set the RSA public key to the server's public key
        client.setServerKeys(input.getPublicKey());
        return new ClientHandshakeProtocol(client);
    }
}
