package org.haox.kerb.common.event;

import org.haox.kerb.common.transport.KrbTransport;

public class NewTransportEvent extends TransportEvent {

    public NewTransportEvent(KrbTransport transport) {
        super(transport, EventType.NEW_TRANSPORT);
    }
}
