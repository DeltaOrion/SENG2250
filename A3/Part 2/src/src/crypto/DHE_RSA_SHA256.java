package src.crypto;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

/**
 * Performs a Diffie hellman key exchange. This will generate
 *   - public and private keys
 *   - a nonce that can be transferred for any reason
 *   - the shared key if given the parameters from a separate party.
 *   - AES 192 bit shared key {@link #getSharedKey()}
 *   - HMAC 256 bit shared key {@link #getkPrime()}
 *
 *   This should be verified using a digital signature from the server side.
 */
public class DHE_RSA_SHA256 {

    //values of the prime modulus and generator, these were given by the assignment spec
    public final static BigInteger DEFAULT_P = new BigInteger("178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239",10);
    private final static BigInteger DEFAULT_G = new BigInteger("174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730",10);

    private final SecureRandom random;
    //192 bit AES encryption key K where K is the first n bits of k'
    private SecretKey sharedKey;
    //256 bit k' HMAC key where k' = h(g^yx)
    private SecretKey kPrime;
    //private key and public keys for DHE.
    private DHPrivateKeySpec privateKey;
    private DHPublicKeySpec publicKey;

    private BigInteger nonce;

    //key lengths for AES and k'
    public static int DEFAULT_KEY_LENGTH = 256;
    public static int DEFAULT_AES_LENGTH = 192;

    public DHE_RSA_SHA256() {
        this.random = new SecureRandom();
    }

    /*
     Generate public keys given THIS party is initializing the DHEKE
     */
    public void generatePublicKey(int bits) {
        //use the generate and prime modulus provided
        generatePublic(DEFAULT_G,DEFAULT_P,bits);
    }

    /*
     * Generate shared keys given the fact that the other party has initiated the DHEKE.
     * Use the prime modulus and generator given by the other party
     */
    public void receiveGenerateShared(DHPublicKeySpec otherKey, int bits, int length) throws NoSuchAlgorithmException {
        generatePublic(otherKey.getG(),otherKey.getP(),bits);
        generateSharedKey(otherKey,length);
    }

    private void generatePublic(BigInteger g, BigInteger p ,int bits) {
        //generate public keys using the public key spec

        //generate X the private key
        BigInteger X = new BigInteger(bits,random);

        //generate public key Y = g^x mod p
        BigInteger Y = MathHelper.modPow(g,X,p);

        //create convenient object to hold keys
        this.publicKey = new DHPublicKeySpec(Y, p, g);
        this.privateKey = new DHPrivateKeySpec(X, p, g);

        //generate nonce, this can be used later for any reason
        this.nonce = new BigInteger(127,random);
    }

    //Generates the shared key using the other key given
    public void generateSharedKey(DHPublicKeySpec otherKey, int length) throws NoSuchAlgorithmException {
        //generate g^yx or k, the initial shared key
        BigInteger sharedKey = MathHelper.modPow(otherKey.getY(),privateKey.getX(),otherKey.getP());

        //calculate k'
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] sharedDigest = sha256.digest(sharedKey.toByteArray());
        //unfortunately the shared AES key is not 256 bits, lets take the first 196 bits;
        byte[] bkey = Arrays.copyOf(
                sharedDigest, length / Byte.SIZE);

        //create shared keys for both algorithms
        this.sharedKey = new SecretKeySpec(bkey, "AES");
        this.kPrime = new SecretKeySpec(sharedDigest,"HMAC");
    }

    public BigInteger getP() {
        return DEFAULT_P;
    }

    public BigInteger getG() {
        return DEFAULT_G;
    }

    public SecretKey getSharedKey() {
        return sharedKey;
    }

    public SecretKey getkPrime() {
        return kPrime;
    }

    public DHPublicKeySpec getPublicKey() {
        return publicKey;
    }

    public BigInteger getNonce() {
        return nonce;
    }
}
