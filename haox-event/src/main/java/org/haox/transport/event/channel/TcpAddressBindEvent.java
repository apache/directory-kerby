package org.haox.transport.event.channel;

import org.haox.transport.event.TransportEventType;

import java.net.InetSocketAddress;

public class TcpAddressBindEvent extends AddressEvent {

    public TcpAddressBindEvent(InetSocketAddress address) {
        super(address, TransportEventType.TCP_ADDRESS_BIND);
    }
}
