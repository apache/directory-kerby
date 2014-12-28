package org.apache.kerberos.kerb.codec.spnego;

import java.io.IOException;

public class SpnegoInitToken extends SpnegoToken {

    public static final int DELEGATION = 0x40;
    public static final int MUTUAL_AUTHENTICATION = 0x20;
    public static final int REPLAY_DETECTION = 0x10;
    public static final int SEQUENCE_CHECKING = 0x08;
    public static final int ANONYMITY = 0x04;
    public static final int CONFIDENTIALITY = 0x02;
    public static final int INTEGRITY = 0x01;

    private String[] mechanisms;
    private int contextFlags;

    public SpnegoInitToken(byte[] token) throws IOException {

    }

    public int getContextFlags() {
        return contextFlags;
    }

    public boolean getContextFlag(int flag) {
        return (getContextFlags() & flag) == flag;
    }

    public String[] getMechanisms() {
        return mechanisms;
    }

}
