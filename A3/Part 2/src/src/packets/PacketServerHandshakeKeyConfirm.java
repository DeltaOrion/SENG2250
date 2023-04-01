package src.packets;

import src.Packet;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Key confirm packet from client to server. This allows the client to verify that the server
 * is in possession of the key providing explicit confirmation. This will encrypt the client
 * nonce to ensure the server is in possession of the key. Using a nonce stops replay attacks.
 * The client can decrypt the nonce sent by the server and check that it is equal to the nonce it sent
 *
 * S -> C (Ns, Nc, E(Ks; Nc)
 */
public class PacketServerHandshakeKeyConfirm extends Packet {

    private final BigInteger nonceClient;
    private final BigInteger nonceServer;
    private final byte[] cipherText;

    public PacketServerHandshakeKeyConfirm(BigInteger nonceClient, BigInteger nonceServer, byte[] cipherText) {
        this.nonceClient = nonceClient;
        this.nonceServer = nonceServer;
        this.cipherText = cipherText;
    }

    @Override
    public PacketType getType() {
        return PacketType.SERVER_HANDSHAKE_KEY_CONFIRM;
    }

    @Override
    protected String getBody() {
        Map<String,Object> map = new LinkedHashMap<>();
        map.put("nonce client",nonceClient);
        map.put("nonce server",nonceServer);
        map.put("ciphertext", new BigInteger(cipherText));
        return constructBody(map);
    }

    @Override
    protected String getName() {
        return "Server Handshake Key Confirm";
    }

    public BigInteger getNonceClient() {
        return nonceClient;
    }

    public BigInteger getNonceServer() {
        return nonceServer;
    }

    public byte[] getCipherText() {
        return cipherText;
    }
}
