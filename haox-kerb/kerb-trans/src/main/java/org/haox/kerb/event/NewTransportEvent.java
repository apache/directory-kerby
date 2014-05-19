package org.haox.kerb.event;

import org.haox.kerb.transport.Transport;

public class NewTransportEvent extends TransportEvent {

    public NewTransportEvent(Transport transport) {
        super(transport, EventType.NEW_TRANSPORT);
    }
}
