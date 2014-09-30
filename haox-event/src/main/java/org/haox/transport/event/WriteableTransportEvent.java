package org.haox.transport.event;

import org.haox.transport.Transport;

public class WriteableTransportEvent extends TransportEvent {

    public WriteableTransportEvent(Transport transport) {
        super(transport, TransportEventType.WRITEABLE_TRANSPORT);
    }
}
