package org.haox.kerb.event;

import org.haox.kerb.transport.Transport;

public abstract class TransportEvent extends Event {

    private Transport transport;

    public TransportEvent(Transport transport, EventType eventType) {
        super(eventType);
        this.transport = transport;
    }

    public Transport getTransport() {
        return transport;
    }
}
