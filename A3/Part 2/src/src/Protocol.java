package src;

/**
 * Represents any protocol utilized for either the client or the server. A protocol should describe
 * what should happen when a packet is received from the other party
 */
public abstract class Protocol {

    public abstract void init();

    //enters the packet received from the other party
    public abstract void setInput(Packet packet);

    //executes the protocol
    public abstract Protocol run() throws UnexpectedPacketException;

    public abstract String getName();

}
