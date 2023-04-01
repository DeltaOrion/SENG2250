package src.packets;

import src.Packet;
import src.TamperedMessageException;
import src.crypto.AESCryptoSystem;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Allows either the client or the server to perform secure data exchange. This allows
 * any message to be sent securely protecting data integrity and confidentiality. On sending the message
 * will be encrypted using CBC AES 192 bit encryption with an appended message authentication code.
 *
 * On receive the message will be decrypted and a new MAC' will be produced. If MAC' != MAC then a TamperedMessageException
 * will be thrown as it will be assume the message was modified in transit
 *
 * C -> S (E(Kcs, Message), MAC, IV)
 */
public class PacketDataExchange extends Packet {

    private byte[] cipherText; //the message stored as ciphertext
    private byte[] MAC; //message authentication code
    private byte[] IV; //the initialization vector used
    private final static int MESSAGE_SIZE = 64; //the message must be exactly 64 bytes

    public PacketDataExchange() {
    }

    //Sets the message, encrypts it and forges a MAC
    public void setMessage(String message, AESCryptoSystem cryptoSystem) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException {
        if(message.getBytes().length!=MESSAGE_SIZE)
            throw new IllegalArgumentException("Invalid Message Size '"+message+"'");

        //create an IV for the CBC
        byte[] IV = cryptoSystem.generateIV();
        cryptoSystem.init(Cipher.ENCRYPT_MODE,IV);

        //forge ciphertext using the shared key
        byte[] cipherText = cryptoSystem.CBC(message.getBytes());
        //forge a MAC to protect message integrity
        byte[] hmac = cryptoSystem.HMAC(cipherText);

        this.IV = IV;
        this.MAC = hmac;
        this.cipherText = cipherText;
    }

    public String getMessage(AESCryptoSystem cryptoSystem) throws TamperedMessageException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //before decryption check that the message has not been tampered with
        byte[] macPrime = cryptoSystem.HMAC(cipherText);
        //if the message has been changed MAC != MAC' then throw the tampered message exception
        if(!Arrays.equals(macPrime,MAC))
            throw new TamperedMessageException("Integrity of the message has been violated! HMAC does not match MAC");

        //return the decrypted message
        cryptoSystem.init(Cipher.DECRYPT_MODE,IV);
        return new String(cryptoSystem.CBC(cipherText));
    }

    @Override
    public PacketType getType() {
        return PacketType.DATA_EXCHANGE;
    }

    @Override
    protected String getBody() {
        Map<String,Object> map = new LinkedHashMap<>();
        map.put("ciphertext",new BigInteger(cipherText));
        map.put("mac",new BigInteger(MAC));
        map.put("IV",new BigInteger(IV));
        return constructBody(map);
    }

    @Override
    protected String getName() {
        return "Data Exchange";
    }
}
