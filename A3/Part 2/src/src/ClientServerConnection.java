package src;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

/**
 * Represents a socket level connection between the client and the server. This is used by both
 * the client and the server. This works by taking a {@link Packet}, serializing it into a stream
 * of bytes and sending it through the wire, where it can then be deserialized and read.
 */
public abstract class ClientServerConnection implements Runnable {

    private final Socket socket;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private Protocol protocol;

    public ClientServerConnection(Socket socket) throws IOException {
        //create the socket and create object output and input streams
        //this will make sending data far easier than sending strings down the wire!
        this.socket = socket;
        out = new ObjectOutputStream(socket.getOutputStream());
        out.flush();
        in = new ObjectInputStream(socket.getInputStream());
    }

    public void init(Protocol initialProtocol) {
        //the starting protocol for the connection. This will then run the setup message if any.
        this.protocol = initialProtocol;
        protocol.init();
    }


    @Override
    public void run() {
        try {
            //read the next object through the wire
            Object inObject = null;
            while ((inObject = in.readObject()) != null) {
                //convert it to a packet. If a non-packet it sent down the wire
                //terminate the connection
                Packet input = (Packet) inObject;
                //handle the packet
                if(!onPacket(input))
                    break;
            }
        } catch (IOException e) {
            System.err.println("A fatal error occurred. Connection aborted: " + e.getMessage());
        } catch (ClassNotFoundException e) {
            System.err.println("Packet Type does not exist. Connection Aborted" + e.getMessage());
        } catch (UnexpectedPacketException e) {
            System.err.println(getClass().getSimpleName());
            System.err.println("Unexpected Packet " + e);
        } finally {
            try {
                //if any error comes just terminate the connection. In reality we would want to try error recovery (especially for
                //unexpected packet). But just keep it simple for now.
                disconnect();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void sendPacket(Packet packet) {
        //send a packet down the wire
        //log the packet we just sent
        logSend(packet);
        try {
            //write the object to the socket
            out.writeObject(packet);
        } catch (IOException e) {
            System.err.println("An error occurred while sending a packet");
            try {
                disconnect();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    public boolean onPacket(Packet packet) throws UnexpectedPacketException {
        //handle the receiving of a packet

        //log the packet we received
        logReceive(packet);

        //enter the packet to the protocol
        protocol.setInput(packet);
        //allow the protocol being used to handle the packet
        Protocol newProtocol = protocol.run();
        if (newProtocol == null) {
            //if a protocol returns null then the program should terminate
            logMessage("-----oO Terminating Oo-----");
            return false;
        }

        if (newProtocol != protocol) {
            //if we swapped protocols log this as well
            protocol = newProtocol;
            logMessage("-----oO Protocol "+protocol.getName()+" Oo-----");
            newProtocol.init();
        }
        return true;
    }

    public void disconnect() throws IOException {
        //terminates the connection
        socket.close();
        in.close();
        out.close();
    }


    private void logReceive(Packet packet) {
        logMessage("Received: " + packet.getLogMessage());
        System.out.println();
    }

    private void logSend(Packet packet) {
        logMessage("Sending: " + packet.getLogMessage());
        System.out.println();
    }

    public boolean isClosed() {
        return socket.isClosed();
    }

    public abstract void logMessage(String message);
}
