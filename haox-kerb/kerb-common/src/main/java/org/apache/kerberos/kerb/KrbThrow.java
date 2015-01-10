package org.apache.kerberos.kerb;

public class KrbThrow {

    public static KrbException out(MessageCode messageCode) throws KrbException {
        throw new KrbException(Message.getMessage(messageCode));
    }

    public static void out(MessageCode messageCode, Exception e) throws KrbException {
        throw new KrbException(Message.getMessage(messageCode), e);
    }

    public static void out(MessageCode messageCode, String message) throws KrbException {
        throw new KrbException(Message.getMessage(messageCode) + ":" + message);
    }
}
