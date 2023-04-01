package src.packets;

import src.Packet;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Hello packet during the handshake from client to server
 *
 * C -> S (Id client)
 */
public class PacketClientHandshakeHello extends Packet {

    private final int clientId;

    public PacketClientHandshakeHello(int clientId) {
        this.clientId = clientId;
    }

    @Override
    public PacketType getType() {
        return PacketType.CLIENT_HANDSHAKE_HELLO;
    }

    @Override
    protected String getBody() {
        Map<String,Object> map = new LinkedHashMap<>();
        map.put("Client ID",clientId);
        return constructBody(map);
    }

    @Override
    protected String getName() {
        return "Client Handshake Hello";
    }

    public int getClientId() {
        return clientId;
    }
}
