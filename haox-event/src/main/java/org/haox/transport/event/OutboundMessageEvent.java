package org.haox.transport.event;

import org.haox.transport.Message;
import org.haox.transport.Transport;

public class OutboundMessageEvent extends MessageEvent {

    public OutboundMessageEvent(Transport transport, Message message) {
        super(transport, message, TransportEventType.OUTBOUND_MESSAGE);
    }
}
