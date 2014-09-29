package org.haox.transport.event.channel;

import org.haox.transport.event.TransportEventType;

import java.net.InetSocketAddress;

public class UdpAddressBindEvent extends AddressEvent {

    public UdpAddressBindEvent(InetSocketAddress address) {
        super(address, TransportEventType.UDP_ADDRESS_BIND);
    }
}
