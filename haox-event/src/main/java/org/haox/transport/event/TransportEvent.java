package org.haox.transport.event;

import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.transport.Transport;

public abstract class TransportEvent extends Event {

    private Transport transport;

    public TransportEvent(Transport transport, EventType eventType) {
        super(eventType);
        this.transport = transport;
    }

    public TransportEvent(Transport transport, EventType eventType, Object eventData) {
        super(eventType, eventData);
        this.transport = transport;
    }

    public Transport getTransport() {
        return transport;
    }
}
