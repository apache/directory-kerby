package org.haox.kerb.transport.connect;

import org.haox.kerb.event.NewTransportEvent;
import org.haox.kerb.transport.AsyncSelector;
import org.haox.kerb.transport.Transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;

public abstract class Connector extends AsyncSelector {

    public Connector() {
        super();
    }

    public void connect(String serverAddress, short serverPort) throws IOException {
        InetSocketAddress sa = new InetSocketAddress(serverAddress, serverPort);
        doConnect(sa);
    }

    protected abstract void doConnect(InetSocketAddress sa) throws IOException;

    protected abstract void dealKey(SelectionKey selectionKey) throws IOException;

    protected void onNewTransport(Transport transport) {
        transport.setDispatcher(getDispatcher());
        getDispatcher().dispatch(new NewTransportEvent(transport));
    }
}
