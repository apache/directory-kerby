package org.haox.kerb.crypto2;

import org.haox.kerb.common.Confounder;

public class Nonce {

    public static synchronized int value() {
        return Confounder.intValue() & 0x7fffffff;
    }

}
