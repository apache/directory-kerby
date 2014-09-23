package org.haox.event;

import org.haox.transport.Transport;

public class ReadableTransportEvent extends TransportEvent {

    public ReadableTransportEvent(Transport transport) {
        super(transport, EventType.READABLE_TRANSPORT);
    }
}
