package org.haox.kerb.spec;

public class KrbThrow {
    public static KrbException out(KrbMessageCode messageCode) throws KrbException {
        throw new KrbException(KrbMessage.getMessage(messageCode));
    }

    public static void out(KrbMessageCode messageCode, Exception e) throws KrbException {
        throw new KrbException(KrbMessage.getMessage(messageCode), e);
    }

    public static void out(KrbMessageCode messageCode, String message) throws KrbException {
        throw new KrbException(KrbMessage.getMessage(messageCode) + ":" + message);
    }
}
