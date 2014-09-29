package org.haox.transport;

import org.haox.event.Dispatcher;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;

public abstract class Connector extends AbstractSelector {

    public Connector(Dispatcher dispatcher) {
        super(dispatcher);
    }

    public void connect(String serverAddress, short serverPort) throws IOException {
        InetSocketAddress sa = new InetSocketAddress(serverAddress, serverPort);
        doConnect(sa);
    }

    protected abstract void doConnect(InetSocketAddress sa) throws IOException;

    protected abstract void dealKey(SelectionKey selectionKey) throws IOException;
}
