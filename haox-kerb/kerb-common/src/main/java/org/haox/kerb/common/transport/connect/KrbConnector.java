package org.haox.kerb.common.transport.connect;

import org.haox.kerb.common.transport.KrbTransport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

public abstract class KrbConnector {
    private String serverAddress;
    private short serverPort;

    public KrbConnector(String serverAddress, short serverPort) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
    }

    public KrbTransport connect() throws IOException {
        SocketAddress sa = new InetSocketAddress(serverAddress, serverPort);
        return doConnect(sa);
    }

    protected abstract KrbTransport doConnect(SocketAddress sa) throws IOException;
}
