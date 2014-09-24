package org.haox.event.channel;

import org.haox.event.Event;
import org.haox.event.EventType;

import java.net.InetSocketAddress;

public abstract class AddressEvent extends Event {

    private InetSocketAddress address;

    public AddressEvent(InetSocketAddress address, EventType eventType) {
        super(eventType);
        this.address = address;
    }

    public InetSocketAddress getAddress() {
        return address;
    }
}
