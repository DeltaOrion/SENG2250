package src;

import src.packets.PacketDataExchange;
import src.util.IdGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Protocol for sending messages down the wire. All messages sent must be encrypted using AES CBC with HMAC appended. All encryption
 * cccurs in {@link PacketDataExchange} allowing the security to be abstracted away. This will sent 2 data exchanges down the wire
 * to demonstrate the secure sending of messages.
 *
 * C -> S (E(Kcs, Message), MAC, IV)
 * S -> C (E(Kcs, Message), MAC, IV)
 */
public class DataExchangeProtocol extends Protocol {

    private int exchanges = 0;
    //whether this secure entity should initiate the data exchange
    private final boolean initiate;
    //the entity performing the data exchange
    private final SecureEntity secureEntity;
    private Packet input;

    public DataExchangeProtocol(boolean initiate, SecureEntity entity) {
        this.initiate = initiate;
        this.secureEntity = entity;
        this.input = null;
    }

    @Override
    public void init() {
        if(initiate) {
            try {
                //if we initiate then send the message first
                sendMessage();
            } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
                e.printStackTrace();
            }
        }
    }

    private void sendMessage() throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        exchanges++;
        PacketDataExchange dataExchange = new PacketDataExchange();
        String message = "This is an awesome data exchange. I need 64 character. Message#"+ IdGenerator.getInstance().generateId();
        //ENCRYPTION AND DATA INTEGRITY CHECKS ARE DONE INSIDE OF dataExchange#setMessage()!!!!
        //This allows all of the security to be abstracted away allowing the
        //user to quickly set the contents of the contents of the packet
        dataExchange.setMessage(message,secureEntity.getCryptoSystem());

        //log the message we sent
        secureEntity.logMessage("---------------------------");
        secureEntity.logMessage("SENT MESSAGE: "+message);
        secureEntity.logMessage("---------------------------");
        secureEntity.sendPacket(dataExchange);
    }

    @Override
    public void setInput(Packet packet) {
        this.input = packet;
    }

    @Override
    public Protocol run() throws UnexpectedPacketException {
        switch (input.getType()) {
            case DATA_EXCHANGE:
                return handleExchange((PacketDataExchange) input);
            default:
                throw new UnexpectedPacketException();
        }
    }

    @Override
    public String getName() {
        return "Data Exchange";
    }

    private Protocol handleExchange(PacketDataExchange packet) throws UnexpectedPacketException {
        try {
            //log the message we received
            String message = packet.getMessage(secureEntity.getCryptoSystem());
            secureEntity.logMessage("---------------------------");
            secureEntity.logMessage("RETRIEVED MESSAGE: "+message);
            secureEntity.logMessage("---------------------------");

            //if we have done two exchange then terminate
            if(exchanges==2)
                return null;

            //send a new message
            sendMessage();
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new UnexpectedPacketException(e);
        } catch (TamperedMessageException e) {
            secureEntity.logMessage("RECEIVED MESSAGE HAS BEEN TAMPERED. TERMINATING COMMUNICATION");
            throw new UnexpectedPacketException(e);
        }

        //if we did not initiate then we need to wait for the final message!
        if(exchanges>=2 && !initiate)
            return null;

        return this;
    }
}
