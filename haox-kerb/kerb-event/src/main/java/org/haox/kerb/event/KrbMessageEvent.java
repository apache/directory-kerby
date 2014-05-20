package org.haox.kerb.event;

import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.transport.Transport;

public abstract class KrbMessageEvent extends TransportEvent {

    private KrbMessage message;

    public KrbMessageEvent(Transport transport, KrbMessage message, EventType eventType) {
        super(transport, eventType);
        this.message = message;
    }

    public KrbMessage getMessage() {
        return message;
    }
}
