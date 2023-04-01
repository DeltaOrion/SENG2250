package src.packets;

import src.Packet;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Hello packet during the handshake from client to server.
 * This is the setup request and forms the first message that the client should send to the server
 * to initiate a connection. The message can contain anything but should generally say Hello!
 *
 * C -> S (message)
 */
public class PacketClientSetupHello extends Packet {

    private final String message;

    public PacketClientSetupHello(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public PacketType getType() {
        return PacketType.CLIENT_SETUP_HELLO;
    }

    @Override
    protected String getBody() {
        Map<String,Object> attributes = new LinkedHashMap<>();
        attributes.put("message",message);
        return constructBody(attributes);
    }

    @Override
    protected String getName() {
        return "Client Setup Request Hello";
    }
}
