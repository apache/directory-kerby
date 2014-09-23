package org.haox.event;

import org.haox.message.Message;
import org.haox.transport.Transport;

public class NewOutboundMessageEvent extends MessageEvent {

    public NewOutboundMessageEvent(Transport transport, Message message) {
        super(transport, message, EventType.NEW_OUTBOUND_MESSAGE);
    }
}
