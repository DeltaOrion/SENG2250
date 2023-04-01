package src.crypto;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class MathHelper {

    /*
     * Function to perform fast modular exponentiation
     */
    public static BigInteger modPow(BigInteger base ,BigInteger exponent, BigInteger modulus) {
        //handle trivial case
        if(exponent.equals(BigInteger.ONE))
            return BigInteger.ZERO;

        BigInteger rs = BigInteger.ONE;

        while (exponent.compareTo(BigInteger.ZERO)>0) {
            if (exponent.and(BigInteger.ONE).equals(BigInteger.ONE))
                rs = (rs.multiply(base)).mod(modulus);
            //e = e/2
            exponent = exponent.shiftRight(1);
            base = (base.multiply(base).mod(modulus));
        }
        return rs;
    }

    public static byte[] mergeByteArrays(byte[]... message) {
        //merges n byte arrays
        int length = 0;
        for(byte[] m : message) {
            length+=m.length;
        }
        ByteBuffer buffer = ByteBuffer.allocate(length);
        for(byte[] object : message) {
            buffer.put(object);
        }
        return buffer.array();
    }

}
