package src;

import src.packets.PacketType;

import java.io.Serializable;
import java.util.Map;

/**
 * Represents any packet sent between two parties. A packet should contain
 * information to be transferred between the client and the sever.
 */
public abstract class Packet implements Serializable {

    public abstract PacketType getType();

    protected String constructBody(Map<String,Object> attributes) {
        StringBuilder builder = new StringBuilder();
        //present all of the supplied attributes of the packet in an easy to read
        //format
        for(Map.Entry<String,Object> attribute : attributes.entrySet()) {
            builder.append("\n  \"")
                    .append(attribute.getKey())
                    .append("\"")
                    .append(": ")
                    .append(attribute.getValue());
        }
        return builder.toString();
    }

    public String getLogMessage() {
        return getName() + ": {"
                + getBody() + "\n"
                + "}";
    }

    protected abstract String getBody();

    protected abstract String getName();

}
