package src.packets;

import src.Packet;

import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Packet for performing the diffie hellman key exchange from the server to the client. This will store
 * S -> C (g^x,g,p,Ns, sig {Es, Ns, g, g^x})
 *
 * The client on retrieval will ensure that the digital signature is accurate
 */
public class PacketServerHandshakeDHE extends Packet {

    private final BigInteger Y;
    private final BigInteger P;
    private final BigInteger G;
    private final BigInteger nonce;
    private final BigInteger digitalSignature;

    public PacketServerHandshakeDHE(DHPublicKeySpec publicKey, BigInteger nonce, BigInteger digitalSignature) {
        this.Y = publicKey.getY();
        this.P = publicKey.getP();
        this.G = publicKey.getG();
        this.nonce = nonce;
        this.digitalSignature = digitalSignature;
    }

    @Override
    public PacketType getType() {
        return PacketType.SERVER_HANDSHAKE_RSA_DHE;
    }

    @Override
    protected String getBody() {
        Map<String,Object> attributes = new LinkedHashMap<>();
        attributes.put("g",G);
        attributes.put("p",P);
        attributes.put("y",Y);
        attributes.put("nonce",nonce);
        attributes.put("signature",digitalSignature);
        return constructBody(attributes);
    }

    @Override
    protected String getName() {
        return "Server Handshake Ephemeral Diffie Hellman Key Exchange";
    }

    public BigInteger getNonce() {
        return nonce;
    }

    public DHPublicKeySpec getPublicKey() {
        return new DHPublicKeySpec(Y,P,G);
    }

    public BigInteger getDigitalSignature() {
        return digitalSignature;
    }
}
