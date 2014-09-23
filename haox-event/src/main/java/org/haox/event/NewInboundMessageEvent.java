package org.haox.event;

import org.haox.message.Message;
import org.haox.transport.Transport;

public class NewInboundMessageEvent extends MessageEvent {

    public NewInboundMessageEvent(Transport transport, Message message) {
        super(transport, message, EventType.NEW_INBOUND_MESSAGE);
    }
}
