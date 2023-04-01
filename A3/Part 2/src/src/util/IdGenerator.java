package src.util;

public class IdGenerator {

    private static IdGenerator instance;
    private int id;

    /*
     * Small utility to generate unique ids for client or server
     */
    public static IdGenerator getInstance() {
        if(instance==null) {
            instance = new IdGenerator();
        }
        return instance;
    }

    public int generateId() {
        return id++;
    }

}
