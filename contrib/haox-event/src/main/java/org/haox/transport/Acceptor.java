package org.haox.transport;

import java.net.InetSocketAddress;

public abstract class Acceptor extends TransportSelector {

    public Acceptor(TransportHandler transportHandler) {
        super(transportHandler);
    }

    public void listen(String address, short listenPort) {
        InetSocketAddress socketAddress = new InetSocketAddress(address, listenPort);
        doListen(socketAddress);
    }

    protected abstract void doListen(InetSocketAddress socketAddress);
}
