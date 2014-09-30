package org.haox.transport.event;

import org.haox.transport.Message;
import org.haox.transport.Transport;

public class InboundMessageEvent extends MessageEvent {

    public InboundMessageEvent(Transport transport, Message message) {
        super(transport, message, TransportEventType.INBOUND_MESSAGE);
    }
}
