package src;

import src.crypto.AESCryptoSystem;
import src.crypto.DHE_RSA_SHA256;
import src.crypto.RSA;

/**
 * Represents an entity (client or server) that can send messages securely between them using a shared
 * key and cryptosystem. The entity should be able to perform a diffie hellman key-exchange.
 */
public interface SecureEntity {

    DHE_RSA_SHA256 getDHE();

    RSA getRSA();

    AESCryptoSystem getCryptoSystem();

    void sendPacket(Packet packet);

    void logMessage(String message);
}
