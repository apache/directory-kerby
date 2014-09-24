package org.haox.event.channel;

import org.haox.event.EventType;

import java.net.InetSocketAddress;

public class TcpAddressBindEvent extends AddressEvent {

    public TcpAddressBindEvent(InetSocketAddress address) {
        super(address, EventType.TCP_ADDRESS_BIND);
    }
}
