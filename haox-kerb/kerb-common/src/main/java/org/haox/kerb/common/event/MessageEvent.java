package org.haox.kerb.common.event;

import org.haox.kerb.common.transport.KrbTransport;
import org.haox.kerb.spec.type.common.KrbMessage;

public abstract class MessageEvent extends TransportEvent {

    private KrbMessage message;

    public MessageEvent(KrbTransport transport, KrbMessage message, EventType eventType) {
        super(transport, eventType);
        this.message = message;
    }

    public KrbMessage getMessage() {
        return message;
    }
}
