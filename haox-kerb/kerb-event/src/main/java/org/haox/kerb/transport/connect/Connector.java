package org.haox.kerb.transport.connect;

import org.haox.kerb.dispatch.Dispatcher;
import org.haox.kerb.event.NewTransportEvent;
import org.haox.kerb.transport.Transport;

import java.io.IOException;
import java.net.InetSocketAddress;

public abstract class Connector {
    private Dispatcher dispatcher;

    public Connector() {

    }

    public void setDispatcher(Dispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    public Transport connect(String serverAddress, short serverPort) throws IOException {
        InetSocketAddress sa = new InetSocketAddress(serverAddress, serverPort);
        Transport transport = doConnect(sa);
        onNewTransport(transport);
        return transport;
    }

    protected abstract Transport doConnect(InetSocketAddress sa) throws IOException;

    protected void onNewTransport(Transport transport) {
        transport.setDispatcher(dispatcher);
        dispatcher.dispatch(new NewTransportEvent(transport));
    }
}
