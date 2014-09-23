package org.haox.event.channel;

import org.haox.event.EventType;

import java.net.InetSocketAddress;

public class TcpAddressConnectEvent extends AddressEvent {

    public TcpAddressConnectEvent(InetSocketAddress address) {
        super(address, EventType.TCP_ADDRESS_CONNECT);
    }
}
