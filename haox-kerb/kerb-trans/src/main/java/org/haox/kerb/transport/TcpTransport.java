package org.haox.kerb.transport;

import java.nio.channels.SocketChannel;

public class TcpTransport extends Transport {

    private SocketChannel channel;

    public TcpTransport(SocketChannel channel, boolean isActive) {
        super(isActive);
        this.channel = channel;
    }

}
