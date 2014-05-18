package org.haox.kerb.common.event;

import org.haox.kerb.common.transport.KrbTransport;

public abstract class TransportEvent extends KrbEvent {

    private KrbTransport transport;

    public TransportEvent(KrbTransport transport, EventType eventType) {
        super(eventType);
        this.transport = transport;
    }

    public KrbTransport getTransport() {
        return transport;
    }
}
