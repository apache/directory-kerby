package org.haox.kerb.event;

import org.haox.kerb.transport.Transport;

public class ReadableTransportEvent extends TransportEvent {

    public ReadableTransportEvent(Transport transport) {
        super(transport, EventType.READABLE_TRANSPORT);
    }
}
