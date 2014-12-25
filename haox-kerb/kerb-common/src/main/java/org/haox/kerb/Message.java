package org.haox.kerb;

import java.util.HashMap;
import java.util.Map;

public class Message {
    private static Map<MessageCode, String> entries = new HashMap<MessageCode, String>();

    public static void init() {

    }

    public static void define(MessageCode code, String message) {
        entries.put(code, message);
    }

    public static String getMessage(MessageCode code) {
        String msg = entries.get(code);
        if (msg == null) {
            msg = code.getCodeName();
        }
        return msg;
    }
}
