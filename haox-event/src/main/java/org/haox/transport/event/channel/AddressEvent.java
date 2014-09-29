package org.haox.transport.event.channel;

import org.haox.event.Event;
import org.haox.transport.event.TransportEventType;

import java.net.InetSocketAddress;

public abstract class AddressEvent extends Event {

    private InetSocketAddress address;

    public AddressEvent(InetSocketAddress address, TransportEventType eventType) {
        super(eventType);
        this.address = address;
    }

    public InetSocketAddress getAddress() {
        return address;
    }
}
