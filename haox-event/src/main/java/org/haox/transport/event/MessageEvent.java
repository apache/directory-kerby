package org.haox.transport.event;

import org.haox.transport.Message;
import org.haox.transport.Transport;

public abstract class MessageEvent extends TransportEvent {

    private Message message;

    public MessageEvent(Transport transport, Message message, TransportEventType eventType) {
        super(transport, eventType);
        this.message = message;
    }

    public Message getMessage() {
        return message;
    }
}
