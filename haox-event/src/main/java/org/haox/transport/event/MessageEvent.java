package org.haox.transport.event;

import org.haox.transport.Message;
import org.haox.transport.Transport;

public abstract class MessageEvent extends TransportEvent {

    public MessageEvent(Transport transport, Message message, TransportEventType eventType) {
        super(transport, eventType, message);
    }

    public Message getMessage() {
        return (Message) getEventData();
    }
}
