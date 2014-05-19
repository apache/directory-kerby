package org.haox.kerb.event;

import org.haox.kerb.transport.Transport;

public class WriteableTransportEvent extends TransportEvent {

    public WriteableTransportEvent(Transport transport) {
        super(transport, EventType.WRITEABLE_TRANSPORT);
    }
}
