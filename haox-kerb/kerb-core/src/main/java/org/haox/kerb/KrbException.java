package org.haox.kerb;

public class KrbException extends Exception {

    public KrbException(String message) {
        super(message);
    }

    public KrbException(String message, Throwable cause) {
        super(message, cause);
    }

    public KrbException(KrbErrorCode errorCode) {
        super(errorCode.getMessage());
    }

    public KrbException(KrbErrorCode errorCode, Throwable cause) {
        super(errorCode.getMessage(), cause);
    }

    public KrbException(KrbErrorCode errorCode, String message) {
        super(message + " with error code: " + errorCode.name());
    }
}
