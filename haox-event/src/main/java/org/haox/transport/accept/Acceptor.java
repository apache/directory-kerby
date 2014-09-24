package org.haox.transport.accept;

import org.haox.transport.AsyncSelector;

import java.net.InetSocketAddress;

public abstract class Acceptor extends AsyncSelector {

    public Acceptor() {
        super();
    }

    public void listen(String address, short listenPort) {
        InetSocketAddress socketAddress = new InetSocketAddress(address, listenPort);
        doListen(socketAddress);
    }

    protected abstract void doListen(InetSocketAddress socketAddress);
}
