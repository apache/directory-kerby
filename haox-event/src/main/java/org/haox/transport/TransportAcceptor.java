package org.haox.transport;

import java.net.InetSocketAddress;

public abstract class TransportAcceptor extends TransportSelector {

    public TransportAcceptor(TransportHandler transportHandler) {
        super(transportHandler);
    }

    public void listen(String address, short listenPort) {
        InetSocketAddress socketAddress = new InetSocketAddress(address, listenPort);
        doListen(socketAddress);
    }

    protected abstract void doListen(InetSocketAddress socketAddress);
}
