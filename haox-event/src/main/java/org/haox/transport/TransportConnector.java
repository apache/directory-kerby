package org.haox.transport;

import java.net.InetSocketAddress;

public abstract class TransportConnector extends TransportSelector {

    public TransportConnector(TransportHandler transportHandler) {
        super(transportHandler);
    }

    public void connect(String serverAddress, short serverPort) {
        InetSocketAddress sa = new InetSocketAddress(serverAddress, serverPort);
        doConnect(sa);
    }

    protected abstract void doConnect(InetSocketAddress sa);
}
