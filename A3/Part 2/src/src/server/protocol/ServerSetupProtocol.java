package src.server.protocol;

import src.Packet;
import src.UnexpectedPacketException;
import src.Protocol;
import src.packets.PacketClientSetupHello;
import src.packets.PacketServerSetupRSAKey;
import src.packets.PacketType;
import src.server.ClientConnection;
import src.server.SecureServer;

/**
 * Represents the actions that the server will take when executing the Setup protocol. The setup protocol
 * works as follows
 *
 * C -> S: Hello Setup Request
 * S -> C: RSA Public Key
 */
public class ServerSetupProtocol extends Protocol {

    private final ClientConnection connection;
    private final SecureServer server;
    private PacketType state = null;
    private Packet input;

    public ServerSetupProtocol(ClientConnection connection, SecureServer server) {
        this.connection = connection;
        this.server = server;
    }

    @Override
    public void init() {

    }

    @Override
    public void setInput(Packet packet) {
        input = packet;
    }

    @Override
    public Protocol run() throws UnexpectedPacketException {
        switch (input.getType()) {
            case CLIENT_SETUP_HELLO:
                return handleClientSetup((PacketClientSetupHello) input);
            default:
                throw new UnexpectedPacketException();
        }
    }

    @Override
    public String getName() {
        return "Setup";
    }

    private Protocol handleClientSetup(PacketClientSetupHello packet) throws UnexpectedPacketException {
        if(state!=null)
            throw new UnexpectedPacketException();

        //we can't really do a lot with the hello message it sent so just send the public key
        state = packet.getType();

        //send the public key to the client
        //assume that this is sent securely
        PacketServerSetupRSAKey RSA = new PacketServerSetupRSAKey(
                server.getRSA().getPublicKey()
        );

        connection.sendPacket(RSA);
        return new ServerHandshakeProtocol(server,connection);
    }
}
