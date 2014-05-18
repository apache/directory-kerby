package org.haox.kerb.common.transport.connect;

import org.haox.kerb.common.transport.KrbTransport;
import org.haox.kerb.common.transport.UdpTransport;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.DatagramChannel;

public class UdpConnector extends KrbConnector {
    private String serverAddress;
    private short serverPort;

    public UdpConnector(String serverAddress, short serverPort) {
        super(serverAddress, serverPort);
    }

    @Override
    protected KrbTransport doConnect(SocketAddress sa) throws IOException {
        DatagramChannel channel = DatagramChannel.open();
        channel.configureBlocking(true);
        channel.connect(sa);

        return new UdpTransport(channel, true);
    }
}
