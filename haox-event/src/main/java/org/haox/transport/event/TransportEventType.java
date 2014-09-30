package org.haox.transport.event;

import org.haox.event.EventType;

public enum TransportEventType implements EventType {
    TCP_ADDRESS_BIND,
    TCP_ADDRESS_CONNECT,
    UDP_ADDRESS_BIND,
    UDP_ADDRESS_CONNECT,
    CHANNEL_ACCEPT,
    CHANNEL_CONNECT,
    NEW_TRANSPORT,
    WRITEABLE_TRANSPORT,
    READABLE_TRANSPORT,
    INBOUND_MESSAGE,
    OUTBOUND_MESSAGE
}
