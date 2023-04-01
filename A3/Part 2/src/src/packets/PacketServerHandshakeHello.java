package src.packets;

import src.Packet;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Hello Packet from server to client. This ensures that the client is aware of the session and
 * the id the session that is being used to allow it to resume communications.
 *
 * S -> C (IDs, Sid)
 */
public class PacketServerHandshakeHello extends Packet {
    private final int serverId;
    private final int sessionId;

    public PacketServerHandshakeHello(int serverId, int sessionId) {
        this.serverId = serverId;
        this.sessionId = sessionId;
    }

    @Override
    public PacketType getType() {
        return PacketType.SERVER_HANDSHAKE_HELLO;
    }

    @Override
    protected String getBody() {
        Map<String,Object> attributes = new LinkedHashMap<>();
        attributes.put("serverId",serverId);
        attributes.put("sessionId",sessionId);
        return constructBody(attributes);
    }

    @Override
    protected String getName() {
        return "Server Handshake Hello";
    }

    public int getServerId() {
        return serverId;
    }

    public int getSessionId() {
        return sessionId;
    }
}
