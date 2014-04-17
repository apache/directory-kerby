package org.haox.kerb.spec;

public class KrbException extends Exception {
    public KrbException(String message) {
        super(message);
    }

    public KrbException(String message, Throwable cause) {
        super(message, cause);
    }
}
