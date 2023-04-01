package src;

//thrown when an unexpected packet is received during the protocol
//when this is thrown it is usually fatal and means that the connection should be terminated.
public class UnexpectedPacketException extends Exception {

    public UnexpectedPacketException(String message) {
        super(message);
    }

    public UnexpectedPacketException(Throwable e) {
        super(e);
    }

    public UnexpectedPacketException() {
        super();
    }

}
