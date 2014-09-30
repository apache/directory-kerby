package org.haox.transport.event.channel;

import org.haox.transport.event.TransportEventType;

import java.net.InetSocketAddress;

public class UdpAddressConnectEvent extends AddressEvent {

    public UdpAddressConnectEvent(InetSocketAddress address) {
        super(address, TransportEventType.UDP_ADDRESS_CONNECT);
    }
}
