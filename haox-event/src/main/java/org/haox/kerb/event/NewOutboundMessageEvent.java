package org.haox.kerb.event;

import org.haox.kerb.message.Message;
import org.haox.kerb.transport.Transport;

public class NewOutboundMessageEvent extends MessageEvent {

    public NewOutboundMessageEvent(Transport transport, Message message) {
        super(transport, message, EventType.NEW_OUTBOUND_MESSAGE);
    }
}
