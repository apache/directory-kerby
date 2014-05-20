package org.haox.kerb.handler;

import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.transport.Transport;

public class KrbHandleContext {
    private Transport transport;
    private KrbMessage message;

    public KrbHandleContext(Transport transport) {
        this.transport = transport;
    }

    public void sendMessage(KrbMessage message) {
        //transport.postMessage(message);
    }
}
