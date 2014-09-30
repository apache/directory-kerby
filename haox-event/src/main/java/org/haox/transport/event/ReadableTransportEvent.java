package org.haox.transport.event;

import org.haox.transport.Transport;

public class ReadableTransportEvent extends TransportEvent {

    public ReadableTransportEvent(Transport transport) {
        super(transport, TransportEventType.READABLE_TRANSPORT);
    }
}
