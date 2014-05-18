package org.haox.kerb.common.event;

import org.haox.kerb.common.transport.KrbTransport;

public class ReadableTransportEvent extends TransportEvent {

    public ReadableTransportEvent(KrbTransport transport) {
        super(transport, EventType.READABLE_TRANSPORT);
    }
}
