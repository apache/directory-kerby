package org.haox.transport;

import org.haox.event.*;
import org.haox.transport.AbstractSelector;
import org.haox.transport.event.TransportEventType;
import org.haox.transport.event.channel.UdpAddressConnectEvent;

import java.net.InetSocketAddress;

public abstract class Acceptor extends AbstractSelector {

    public Acceptor(Dispatcher dispatcher) {
        super(dispatcher);
    }

    public void listen(String address, short listenPort) {
        InetSocketAddress socketAddress = new InetSocketAddress(address, listenPort);
        doListen(socketAddress);
    }

    protected abstract void doListen(InetSocketAddress socketAddress);
}
