package src.packets;

import src.Packet;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Key confirm packet from client to server. This allows the server to verify that the client
 * is in possession of the key providing explicit confirmation. This will encrypt the servers
 * nonce to ensure the client is in possession of the key. Using a nonce stops replay attacks.
 * The server can then decrypt the message and check it is equal to the nonce it sent
 *
 * C -> S (Ns, Nc, E(Ks, Ns)
 */
public class PacketClientHandshakeKeyConfirm extends Packet {

    private final BigInteger nonceServer;
    private final BigInteger nonceClient;
    private final byte[] cipherText;

    public PacketClientHandshakeKeyConfirm(BigInteger nonceServer, BigInteger nonceClient, byte[] cipherText) {
        this.nonceClient = nonceClient;
        this.nonceServer = nonceServer;
        this.cipherText = cipherText;
    }

    @Override
    public PacketType getType() {
        return PacketType.CLIENT_HANDSHAKE_KEY_CONFIRM;
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
        return "Client Handshake Key Confirm";
    }

    public BigInteger getNonceServer() {
        return nonceServer;
    }

    public BigInteger getNonceClient() {
        return nonceClient;
    }

    public byte[] getCipherText() {
        return cipherText;
    }
}
