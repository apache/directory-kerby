package org.apache.haox.transport.tcp;

import org.apache.haox.transport.event.AddressEvent;

import java.net.InetSocketAddress;

public class TcpAddressEvent {

    public static AddressEvent createAddressBindEvent(InetSocketAddress address) {
        return new AddressEvent(address, TcpEventType.ADDRESS_BIND);
    }

    public static AddressEvent createAddressConnectEvent(InetSocketAddress address) {
        return new AddressEvent(address, TcpEventType.ADDRESS_CONNECT);
    }

}
