package org.apache.haox.transport.event;

import org.apache.haox.transport.Transport;

import java.nio.ByteBuffer;

public class MessageEvent extends TransportEvent {

    private MessageEvent(Transport transport, ByteBuffer message) {
        super(transport, TransportEventType.INBOUND_MESSAGE, message);
    }

    public ByteBuffer getMessage() {
        return (ByteBuffer) getEventData();
    }

    public static MessageEvent createInboundMessageEvent(
            Transport transport, ByteBuffer message) {
        return new MessageEvent(transport, message);
    }

}
