package org.haox.kerb.spec;

import java.util.HashMap;
import java.util.Map;

public class KrbMessage {
    private static Map<KrbMessageCode, String> entries = new HashMap<KrbMessageCode, String>();

    public static void init() {
        define(KrbTypeMessageCode.INVALID_KRB_TYPE, "Invalid krb type");
    }

    public static void define(KrbMessageCode code, String message) {
        entries.put(code, message);
    }

    public static String getMessage(KrbMessageCode code) {
        String msg = entries.get(code);
        if (msg == null) {
            msg = code.getCodeName();
        }
        return msg;
    }
}
