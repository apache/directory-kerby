package org.haox.kerb.common.handler;

import org.haox.kerb.common.transport.KrbTransport;
import org.haox.kerb.spec.type.common.KrbMessage;

public class HandleContext {
    private KrbTransport transport;
    private KrbMessage message;

    public HandleContext(KrbTransport transport) {
        this.transport = transport;
    }

    public void sendMessage(KrbMessage message) {
        transport.sendMessage(message);
    }
}
