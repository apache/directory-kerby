package org.haox.transport.event;

import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.transport.Transport;

import java.nio.ByteBuffer;

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
