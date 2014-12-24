package org.haox.transport.event;

import org.haox.event.Event;
import org.haox.event.EventType;

import java.net.InetSocketAddress;

public class AddressEvent extends Event {

    private InetSocketAddress address;

    public AddressEvent(InetSocketAddress address, EventType eventType) {
        super(eventType);
        this.address = address;
    }

    public InetSocketAddress getAddress() {
        return address;
    }
}
