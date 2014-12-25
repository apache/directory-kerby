package org.apache.haox.transport.event;

import org.apache.haox.event.Event;
import org.apache.haox.event.EventType;
import org.apache.haox.transport.Transport;

public class TransportEvent extends Event {

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

    public static TransportEvent createWritableTransportEvent(Transport transport) {
        return new TransportEvent(transport, TransportEventType.TRANSPORT_WRITABLE);
    }

    public static TransportEvent createReadableTransportEvent(Transport transport) {
        return new TransportEvent(transport, TransportEventType.TRANSPORT_READABLE);
    }

    public static TransportEvent createNewTransportEvent(Transport transport) {
        return new TransportEvent(transport, TransportEventType.NEW_TRANSPORT);
    }

}
