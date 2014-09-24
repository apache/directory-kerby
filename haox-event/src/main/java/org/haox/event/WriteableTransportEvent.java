package org.haox.event;

import org.haox.transport.Transport;

public class WriteableTransportEvent extends TransportEvent {

    public WriteableTransportEvent(Transport transport) {
        super(transport, EventType.WRITEABLE_TRANSPORT);
    }
}
