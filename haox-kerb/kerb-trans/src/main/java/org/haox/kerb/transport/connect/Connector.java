package org.haox.kerb.transport.connect;

import org.haox.kerb.transport.Transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

public abstract class Connector {
    private String serverAddress;
    private short serverPort;

    public Connector(String serverAddress, short serverPort) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
    }

    public Transport connect() throws IOException {
        SocketAddress sa = new InetSocketAddress(serverAddress, serverPort);
        return doConnect(sa);
    }

    protected abstract Transport doConnect(SocketAddress sa) throws IOException;
}
