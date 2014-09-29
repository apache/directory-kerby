package org.haox.transport.event.channel;

import org.haox.transport.event.TransportEventType;

import java.net.InetSocketAddress;

public class TcpAddressConnectEvent extends AddressEvent {

    public TcpAddressConnectEvent(InetSocketAddress address) {
        super(address, TransportEventType.TCP_ADDRESS_CONNECT);
    }
}
