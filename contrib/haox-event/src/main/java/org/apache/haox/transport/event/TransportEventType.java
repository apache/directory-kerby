package org.apache.haox.transport.event;

import org.apache.haox.event.EventType;

public enum TransportEventType implements EventType {
    NEW_TRANSPORT,
    TRANSPORT_WRITABLE,
    TRANSPORT_READABLE,
    INBOUND_MESSAGE
}
