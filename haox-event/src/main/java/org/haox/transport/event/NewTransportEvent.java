package org.haox.transport.event;

import org.haox.transport.Transport;

public class NewTransportEvent extends TransportEvent {

    public NewTransportEvent(Transport transport) {
        super(transport, TransportEventType.NEW_TRANSPORT);
    }
}
