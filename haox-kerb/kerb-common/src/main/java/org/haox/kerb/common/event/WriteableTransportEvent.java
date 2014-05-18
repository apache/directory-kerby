package org.haox.kerb.common.event;

import org.haox.kerb.common.transport.KrbTransport;

public class WriteableTransportEvent extends TransportEvent {

    public WriteableTransportEvent(KrbTransport transport) {
        super(transport, EventType.WRITEABLE_TRANSPORT);
    }
}
