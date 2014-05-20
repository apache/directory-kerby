package org.haox.kerb.transport.connect;

import org.haox.kerb.transport.Transport;
import org.haox.kerb.transport.UdpTransport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;

public class UdpConnector extends Connector {
    private String serverAddress;
    private short serverPort;

    public UdpConnector() {
        super();
    }

    @Override
    protected Transport doConnect(InetSocketAddress sa) throws IOException {
        DatagramChannel channel = DatagramChannel.open();
        channel.configureBlocking(true);
        channel.connect(sa);

        return new UdpTransport(channel, sa, true);
    }
}
