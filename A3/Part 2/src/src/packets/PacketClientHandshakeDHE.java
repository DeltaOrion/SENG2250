package src.packets;

import src.Packet;

import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Packet for performing the diffie hellman key exchange from the client to the server
 *
 * C -> S (g^x, g, p)
 */
public class PacketClientHandshakeDHE extends Packet {

    //all the constituent components of the public key
    private final BigInteger Y;
    private final BigInteger G;
    private final BigInteger P;

    public PacketClientHandshakeDHE(DHPublicKeySpec publicKey) {
        this.Y = publicKey.getY();
        this.P = publicKey.getP();
        this.G = publicKey.getG();
    }

    @Override
    public PacketType getType() {
        return PacketType.CLIENT_HANDSHAKE_RSA_DHE;
    }

    @Override
    protected String getBody() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("G", G);
        map.put("P", P);
        map.put("Y", Y);
        return constructBody(map);
    }

    @Override
    protected String getName() {
        return "Client Handshake Ephemeral Diffie Hellman Key Exchange";
    }

    public DHPublicKeySpec getPublicKey() {
        return new DHPublicKeySpec(Y,P,G);
    }
}
