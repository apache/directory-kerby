package org.haox.transport.event;

import org.haox.transport.Transport;

import java.nio.ByteBuffer;

public abstract class MessageEvent extends TransportEvent {

    public MessageEvent(Transport transport, ByteBuffer message, TransportEventType eventType) {
        super(transport, eventType, message);
    }

    public ByteBuffer getMessage() {
        return (ByteBuffer) getEventData();
    }
}
