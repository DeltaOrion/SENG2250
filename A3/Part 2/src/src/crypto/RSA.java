package src.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class RSA {

    private final static int DEFAULT_E = 65537;

    private final SecureRandom random;
    private RSAPublicKeySpec publicKey;
    private RSAPrivateKeySpec privateKey;

    public RSA() {
        this.random = new SecureRandom();
    }

    /*
     Generates RSA public keys modulus n and public exponent e
     Generate RSA private keys modulus n and private exponent d
     */
    public void generateKeys(int bits) {
        //generate p and q, ensure that p and q are prime
        int nbits = bits/2;
        BigInteger p = new BigInteger(nbits,random).nextProbablePrime();
        BigInteger q = new BigInteger(nbits,random).nextProbablePrime();

        //calculate public and private modulus n
        BigInteger n = p.multiply(q);
        //calculate public exponent e
        BigInteger e = BigInteger.valueOf(DEFAULT_E);

        //calculate p-1 and q-1
        BigInteger p1 = p.subtract(BigInteger.ONE);
        BigInteger q1 = q.subtract(BigInteger.ONE);
        //calculate phi(N) = (p-1)(q-1)
        BigInteger phiN = p1.multiply(q1);

        //1 = de(mod λ(n))
        BigInteger d = e.modInverse(phiN);

        this.publicKey = new RSAPublicKeySpec(n,e);
        this.privateKey = new RSAPrivateKeySpec(n,d);
    }

    public void setKeys(RSAPublicKeySpec publicKey) {
        //sets the RSA key. This is useful
        //if another party has sent their public key
        //and calculations need to be done using it
        this.publicKey = new RSAPublicKeySpec(publicKey.getModulus(),publicKey.getPublicExponent());
    }

    public RSAPublicKeySpec getPublicKey() {
        return publicKey;
    }

    public BigInteger encrypt(BigInteger message) {
        return encrypt(message, this.publicKey);
    }

    public BigInteger encrypt(BigInteger message, RSAPublicKeySpec publicKey) {
        //encrypt using public key, that way the message can only be decrypted with private key
        return encrypt(message,publicKey.getPublicExponent(),publicKey.getModulus());
    }

    public BigInteger encrypt(BigInteger message, BigInteger exponent, BigInteger modulus) {
        return MathHelper.modPow(message,exponent,modulus);
    }

    public BigInteger decrypt(BigInteger cipherText) {
        return encrypt(cipherText,privateKey.getPrivateExponent(),privateKey.getModulus());
    }

    public BigInteger decrypt(BigInteger cipherText, BigInteger exponent, BigInteger modulus) {
        return encrypt(cipherText,exponent,modulus);
    }

    private BigInteger digitalSignature(BigInteger message) {
        //This assumes that the message is a digest
        //encrypt with the private key so that anyone cna decrypt it
        //this provides the signature as only this party who owns the private key could have
        //signed it
        return encrypt(message,privateKey.getPrivateExponent(),privateKey.getModulus());
    }

    public BigInteger digitalSignature(byte[]... message) throws NoSuchAlgorithmException {
        //form a digital signature using the message
        //get the digest of the message using getSigDigest() then
        //encrypt using the private key
        return digitalSignature(getSigDigest(message));
    }

    private BigInteger getSigDigest(byte[][] message) throws NoSuchAlgorithmException {
        return getSigDigest(MathHelper.mergeByteArrays(message));
    }

    private BigInteger getSigDigest(byte[] message) throws NoSuchAlgorithmException {
        //create a message digest
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] bkey = sha256.digest(message);
        //rsa message must be greater than 0
        return new BigInteger(bkey).abs();
    }


    public boolean verifySignature(BigInteger signature, byte[]... message) throws NoSuchAlgorithmException {
        return decrypt(signature,publicKey.getPublicExponent(),publicKey.getModulus()).equals(
                getSigDigest(message));
    }
}
