package org.haox.kerb.event.channel;

import org.haox.kerb.event.EventType;

import java.net.InetSocketAddress;

public class UdpAddressBindEvent extends AddressEvent {

    public UdpAddressBindEvent(InetSocketAddress address) {
        super(address, EventType.UDP_ADDRESS_BIND);
    }
}
