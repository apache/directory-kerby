package org.haox.transport.event;

import org.haox.transport.Transport;

import java.nio.ByteBuffer;

public class InboundMessageEvent extends MessageEvent {

    public InboundMessageEvent(Transport transport, ByteBuffer message) {
        super(transport, message, TransportEventType.INBOUND_MESSAGE);
    }
}
