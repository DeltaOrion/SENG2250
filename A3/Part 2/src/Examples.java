import src.crypto.AESCryptoSystem;
import src.crypto.DHE_RSA_SHA256;
import src.crypto.RSA;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Provides examples of all the cryptosystems in use.
 */
public class Examples {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("---- DHE -----");
        exampleDHE();
        System.out.println("---- RSA ----");
        exampleRSA();
        System.out.println("---- AES ----");
        exampleAES();
    }

    private static void exampleDHE() throws InvalidKeyException, NoSuchAlgorithmException {
        DHE_RSA_SHA256 bob = new DHE_RSA_SHA256();
        DHE_RSA_SHA256 alice = new DHE_RSA_SHA256();

        int keyLength = DHE_RSA_SHA256.DEFAULT_KEY_LENGTH;
        int sharedKeyLength = DHE_RSA_SHA256.DEFAULT_AES_LENGTH;

        //bob generates public keys
        bob.generatePublicKey(keyLength);

        //bob sends public keys to alice and generates the shared key
        alice.receiveGenerateShared(bob.getPublicKey(),keyLength,sharedKeyLength);

        //alice sends public key to bob
        bob.generateSharedKey(alice.getPublicKey(), sharedKeyLength);

        //NOTE -  Shared key is just the first 192 bits of k'
        //This is because the AES key must be 192 bits whereas k' is 256 bits!
        System.out.println("Shared Key Length: " + bob.getSharedKey().getEncoded().length * Byte.SIZE);
        System.out.println("K Prime Length: " + bob.getkPrime().getEncoded().length * Byte.SIZE);

        System.out.println("Keys Equal: " + bob.getSharedKey().equals(alice.getSharedKey()));
    }

    private static void exampleRSA() throws NoSuchAlgorithmException {
        RSA server = new RSA();
        //server generate keys
        server.generateKeys(2048);

        //client receives public keys from server
        RSA client = new RSA();
        client.setKeys(server.getPublicKey());
        //client encrypts the message 1234
        BigInteger message = BigInteger.valueOf(1234);
        BigInteger cipherText = client.encrypt(message);

        //check if server decrypt is equal
        BigInteger plainText =server.decrypt(cipherText);
        System.out.println("Messages Equal: " + plainText.equals(message));

        //----- Digital Signature ----///
        BigInteger digitalSignature = server.digitalSignature(message.toByteArray()); //server generate signature
        boolean verification = client.verifySignature(digitalSignature,message.toByteArray()); //client verify signature
        System.out.println("Signature Verified: " + verification);
    }

    private static void exampleAES() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //---- Generate Keys ----//
        DHE_RSA_SHA256 bob = new DHE_RSA_SHA256();
        DHE_RSA_SHA256 alice = new DHE_RSA_SHA256();
        int keyLength = DHE_RSA_SHA256.DEFAULT_KEY_LENGTH;
        int sharedKeyLength = DHE_RSA_SHA256.DEFAULT_AES_LENGTH;
        bob.generatePublicKey(keyLength);
        alice.receiveGenerateShared(bob.getPublicKey(),keyLength,sharedKeyLength);
        bob.generateSharedKey(alice.getPublicKey(), sharedKeyLength);

        // ----- Setup -----//
        AESCryptoSystem server = new AESCryptoSystem();
        AESCryptoSystem client = new AESCryptoSystem();
        server.setKPrime(bob.getkPrime());
        server.setKey(bob.getSharedKey());
        client.setKPrime(alice.getkPrime());
        client.setKey(alice.getSharedKey());

        // ---- Encryption ---//
        //encrypt message using CBC with fresh IV
        String message = "abcdefghijklmnopqrstuvwxyzabcdefghjiklmnopqrstuvwxyzabcdefghijkl";
        byte[] IV = server.generateIV();
        server.init(Cipher.ENCRYPT_MODE,IV);

        byte[] cipherText = server.CBC(message.getBytes());
        //produce HMAC
        byte[] HMAC = server.HMAC(cipherText);

        //---- Decryption -- //
        //decrypt message using CBC

        //produce client side HMAC
        byte[] HMACPrime = server.HMAC(cipherText);
        //client side decrypt
        client.init(Cipher.DECRYPT_MODE,IV);
        String plainText = new String(client.CBC(cipherText));

        //---- Check Equality --//
        System.out.println("Messages Equal:" + plainText.equals(message));
        System.out.println("MAC's Equal: "+ Arrays.equals(HMACPrime, HMAC));
    }
}
