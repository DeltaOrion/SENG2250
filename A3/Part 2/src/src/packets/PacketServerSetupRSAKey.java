package src.packets;

import src.Packet;

import java.math.BigInteger;
import java.security.spec.RSAPublicKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Setup packet from server to client providing the servers public RSA key. It is assumed that this is sent
 * securely from the server to the client removing the need for X.509 certificates.
 *
 * S -> C (e, n)
 */
public class PacketServerSetupRSAKey extends Packet {

    private final BigInteger modulus;
    private final BigInteger publicExponent;

    public PacketServerSetupRSAKey(RSAPublicKeySpec publicKey) {
        this.modulus = publicKey.getModulus();
        this.publicExponent = publicKey.getPublicExponent();
    }


    @Override
    public PacketType getType() {
        return PacketType.SERVER_SETUP_RSA;
    }

    @Override
    protected String getBody() {
        Map<String,Object> map = new LinkedHashMap<>();
        map.put("exponent [e]",publicExponent);
        map.put("Public Key [n]",modulus);
        return constructBody(map);
    }

    @Override
    protected String getName() {
        return "Setup Server's RSA Public Key";
    }

    public RSAPublicKeySpec getPublicKey() {
        return new RSAPublicKeySpec(modulus,publicExponent);
    }
}
