package org.apache.kerberos.kerb.codec.spnego;

import java.io.IOException;

public class SpnegoTargToken extends SpnegoToken {

    public static final int UNSPECIFIED_RESULT = -1;
    public static final int ACCEPT_COMPLETED = 0;
    public static final int ACCEPT_INCOMPLETE = 1;
    public static final int REJECTED = 2;

    private int result = UNSPECIFIED_RESULT;

    public SpnegoTargToken(byte[] token) throws IOException {

    }

    public int getResult() {
        return result;
    }

}
