package org.haox.kerb.event.channel;

import org.haox.kerb.event.EventType;

import java.net.InetSocketAddress;

public class UdpAddressConnectEvent extends AddressEvent {

    public UdpAddressConnectEvent(InetSocketAddress address) {
        super(address, EventType.UDP_ADDRESS_CONNECT);
    }
}
