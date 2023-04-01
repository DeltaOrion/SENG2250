import src.server.SecureServer;

import java.net.InetSocketAddress;

/**
 * Entry Point to the program. Runs the server. This will output all
 * of the packets sent and received by the server.
 */
public class A3Server {

    public static void main(String[] args) {
        //get the port from CLI
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

        //create address using port to local host and run secure server
        InetSocketAddress serverAddress = new InetSocketAddress("localhost",port);
        SecureServer server = new SecureServer(serverAddress);
        server.run();
    }
}
