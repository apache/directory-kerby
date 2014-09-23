package org.haox.event;

import org.haox.message.Message;
import org.haox.transport.Transport;

public abstract class MessageEvent extends TransportEvent {

    private Message message;

    public MessageEvent(Transport transport, Message message, EventType eventType) {
        super(transport, eventType);
        this.message = message;
    }

    public Message getMessage() {
        return message;
    }
}
