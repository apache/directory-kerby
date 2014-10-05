package org.haox.transport.udp;

import org.haox.event.EventType;

public enum UdpEventType implements EventType {
    ADDRESS_BIND,
    ADDRESS_CONNECT,
    CHANNEL_WRITABLE,
    CHANNEL_READABLE
}
