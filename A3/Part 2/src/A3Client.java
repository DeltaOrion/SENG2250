import src.client.SecureClient;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Entry Point to the program. Runs the client. This will output all
 * of the packets sent and received by the server.
 */
public class A3Client {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //get the port
        if(args.length==0) {
            System.err.println("Port not provided");
            return;
        }

        int port;
        try {
            port = Integer.parseInt(args[0]);
        } catch (NumberFormatException e) {
            System.err.println(args[0] + " is not a number!");
            return;
        }

        //create server address and connect to it
        InetSocketAddress serverAddress = new InetSocketAddress("localhost",port);
        SecureClient client = new SecureClient(serverAddress);
        client.run();
    }
}
