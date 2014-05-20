package org.haox.kerb.event;

import org.haox.kerb.message.Message;
import org.haox.kerb.transport.Transport;

public class NewInboundMessageEvent extends MessageEvent {

    public NewInboundMessageEvent(Transport transport, Message message) {
        super(transport, message, EventType.NEW_INBOUND_MESSAGE);
    }
}
