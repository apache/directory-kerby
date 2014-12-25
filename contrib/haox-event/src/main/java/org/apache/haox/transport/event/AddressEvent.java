package org.apache.haox.transport.event;

import org.apache.haox.event.Event;
import org.apache.haox.event.EventType;

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
