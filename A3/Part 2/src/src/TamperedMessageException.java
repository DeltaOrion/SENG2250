package src;

//thrown when the integrity of a message sent cannot be verified
public class TamperedMessageException extends Exception {

    public TamperedMessageException() {
        super();
    }

    public TamperedMessageException(String message) {
        super(message);
    }
}
