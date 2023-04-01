package src.packets;

/*
 * Enum describing all the different types of packets
 */
public enum PacketType {
    //SETUP protocol
    CLIENT_SETUP_HELLO,
    SERVER_SETUP_RSA,

    //HANDSHAKE
    CLIENT_HANDSHAKE_HELLO,
    SERVER_HANDSHAKE_HELLO,
    SERVER_HANDSHAKE_RSA_DHE,
    CLIENT_HANDSHAKE_RSA_DHE,
    SERVER_HANDSHAKE_KEY_CONFIRM,
    CLIENT_HANDSHAKE_KEY_CONFIRM,

    //DATA EXCHANGE
    DATA_EXCHANGE;
}
