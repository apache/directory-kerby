package org.haox.event;

import org.haox.transport.Transport;

public class NewTransportEvent extends TransportEvent {

    public NewTransportEvent(Transport transport) {
        super(transport, EventType.NEW_TRANSPORT);
    }
}
