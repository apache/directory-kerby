package org.haox.kerb.server.tgs;

import org.haox.kerb.server.KdcContext;
import org.haox.kerb.spec.type.common.EncryptionKey;

public class TgsContext extends KdcContext {

    private EncryptionKey tgtSessionKey;

    public EncryptionKey getTgtSessionKey() {
        return tgtSessionKey;
    }

    public void setTgtSessionKey(EncryptionKey tgtSessionKey) {
        this.tgtSessionKey = tgtSessionKey;
    }
}
