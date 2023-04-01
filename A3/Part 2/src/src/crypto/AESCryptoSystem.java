package src.crypto;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Represents the cryptosystem used to securely encrypt messages between the client and the server.
 * Data Confidentiality:
 * For data confidentiality this system uses a 192 bit AES key. It will encrypt using CBC mode without padding. This means
 * messages only of multiples of 128 bit (16 byte) will be accepted. Messages can be encrypted using {@link #CBC(byte[])}.
 * Once should generate a new IV using {@link #generateIV()}
 * 
 * Data Integrity:
 * For integrity this system uses a HMAC code. This should be appended to the end of messages.
 * 
 */
public class AESCryptoSystem {

    //data confidentiality, AES cipher and operational mode
    private final Cipher cipher;
    private int opmode;
    private byte[] IV;
    private final SecureRandom random;
    private final static int BLOCK_SIZE = 16;

    //keys used
    private SecretKey key; //AES 192 bit key
    private SecretKey kPrime; //HMAC 256 bit key

    //HMAC paramaters
    private final static byte O_PAD_VALUE = 0x5c;
    private final static byte I_PAD_VALUE = 0x36;
    private final static int SHA_256_LENGTH = 256;


    public AESCryptoSystem() throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipher = Cipher.getInstance("AES/ECB/NoPadding");
        this.opmode = Cipher.ENCRYPT_MODE;
        this.random = new SecureRandom();
    }

    public void setKey(SecretKey key) throws InvalidKeyException {
        this.key = key;
        cipher.init(opmode,key);
    }

    public void setKPrime(SecretKey kPrime) throws InvalidKeyException {
        //The kPrime key provided should already be hashed using SHA-256, quickly check that
        //the key is the correct size for the OPAD and IPAD XOR
        if(kPrime.getEncoded().length!=SHA_256_LENGTH/Byte.SIZE)
            throw new InvalidKeyException();

        this.kPrime = kPrime;
    }

    public void init(int opmode) throws InvalidKeyException {
        this.opmode = opmode;
        cipher.init(opmode,key);
    }

    public void init(int opmode, byte[] IV) throws InvalidKeyException {
        this.opmode = opmode;
        this.IV = IV;
        cipher.init(opmode,key);
    }

    public byte[] ECB(byte[] message) throws IllegalBlockSizeException, BadPaddingException {
        return cipher.doFinal(message);
    }

    public byte[] generateIV() {
        //IV should be the same size as the block size for CBC.
        byte[] IV = new byte[BLOCK_SIZE];
        random.nextBytes(IV);
        return IV;
    }

    public byte[] CBC(byte[] message) throws IllegalBlockSizeException, BadPaddingException {
        if(message.length%16!=0)
            throw new IllegalBlockSizeException("Message block size must be a multiple of 16");

        if(opmode==Cipher.ENCRYPT_MODE) {
            //encrypt
            return CBCencrypt(message);
        } else {
            //decrypt
            return CBCdecrypt(message);
        }
    }

    //Performs DECRYPTION using CBC mode
    private byte[] CBCdecrypt(byte[] message) throws IllegalBlockSizeException, BadPaddingException {
        byte[] result = new byte[message.length];
        byte[] vector = IV;
        byte[] nextVector;

        //divide the message up into blocks of 16
        for(int i=0;i<message.length;i+=BLOCK_SIZE) {
            //create block of size 16
            byte[] block = Arrays.copyOfRange(message,i,i+BLOCK_SIZE);

            //the next vector to be used in decryption is the previous cipher
            nextVector = Arrays.copyOf(block,block.length);

            //decrypt the cipher block with AES
            block = cipher.doFinal(block);

            //XOR it with the vector to be used (previous cipher)
            for(int j=0;j<block.length;j++) {
                block[j] = (byte) (block[j] ^ vector[j]);
            }

            vector = nextVector;
            //copy decrypted ciphertext to the result array
            System.arraycopy(block, 0, result, i, i + BLOCK_SIZE - i);
        }
        return result;
    }

    //Performs ENCRYPTION using CBC
    private byte[] CBCencrypt(byte[] message) throws IllegalBlockSizeException, BadPaddingException {
        byte[] result = new byte[message.length];
        byte[] vector = IV;

        //divide the message up into blocks of 16
        for(int i=0;i<message.length;i+=BLOCK_SIZE) {
            //create the block of 16
            byte[] block = Arrays.copyOfRange(message,i,i+BLOCK_SIZE);

            //XOR the CBC using the initialization vector or current vector
            for(int j=0;j<block.length;j++) {
                block[j] = (byte) (block[j] ^ vector[j]);
            }

            //encrypt the block with AES
            block = cipher.doFinal(block);
            //the next vector to use is this encrypted block!
            vector = Arrays.copyOf(block,block.length);
            //copy the block to the resultant ciphertext
            System.arraycopy(block, 0, result, i, i + BLOCK_SIZE - i);
        }
        return result;
    }

    //creates a HMAC
    //h(k⊕opad)||h((k⊕ipad)||𝑚𝑚)
    public byte[] HMAC(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        int length = SHA_256_LENGTH/Byte.SIZE;
        byte[] oKeyPad = new byte[length];
        byte[] iKeyPad = new byte[length];
        int count = 0;
        //by looping through the key and XORing
        //this ensures that the IPAD and OPAD are block long repetition
        for(byte b : kPrime.getEncoded()) {
            //XOR the key with the opad and ipad
            oKeyPad[count] = (byte) (b ^ O_PAD_VALUE);
            iKeyPad[count] = (byte) (b ^ I_PAD_VALUE);
        }

        //concatenate the ipad with the message
        //hash ipad concatenated with the message
        //h((k⊕ipad)||𝑚𝑚)
        byte[] ipadConcatMessage = digest.digest(concatArrays(iKeyPad,message));

        //concatenate the hashed ipad message and the opad, hash it
        //and return
        ///h(k⊕opad)||h((k⊕ipad)||𝑚𝑚)
        return digest.digest(concatArrays(oKeyPad,ipadConcatMessage));
    }

    private byte[] concatArrays(byte[] array1, byte[] array2) {
        //concatenates two arrays using System#arrayCopy
        byte[] result = Arrays.copyOf(array1, array1.length + array2.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }

}
