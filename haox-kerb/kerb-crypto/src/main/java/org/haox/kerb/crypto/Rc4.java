package org.haox.kerb.crypto;

public class Rc4 {

    private static byte[] L40 = "fortybits".getBytes();

    public static byte[] getSalt(int usage, boolean exportable) {
        int msUsage = convertUsage(usage);
        byte[] salt;

        if (exportable) {
            salt = new byte[14];
            System.arraycopy(L40, 0, salt, 0, 9);
            BytesUtil.int2bytes(msUsage, salt, 10, false);
        } else {
            salt = new byte[4];
            BytesUtil.int2bytes(msUsage, salt, 0, false);
        }

        return salt;
    }

    public static int convertUsage(int usage) {
        switch (usage) {
            case 3: return 8;
            case 9: return 8;
            case 23: return 13;
            default: return usage;
        }
    }
}
