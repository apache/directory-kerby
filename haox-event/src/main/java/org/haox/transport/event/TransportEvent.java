package org.haox.transport.event;

import org.haox.event.Event;
import org.haox.transport.Transport;

public abstract class TransportEvent extends Event {

    private Transport transport;

    public TransportEvent(Transport transport, TransportEventType eventType) {
        super(eventType);
        this.transport = transport;
    }

    public Transport getTransport() {
        return transport;
    }
}
