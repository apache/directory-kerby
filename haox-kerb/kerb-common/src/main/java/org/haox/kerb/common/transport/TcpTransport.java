package org.haox.kerb.common.transport;

import java.nio.channels.SocketChannel;

public class TcpTransport extends KrbTransport {

    private SocketChannel channel;

    public TcpTransport(SocketChannel channel, boolean isActive) {
        super(isActive);
        this.channel = channel;
    }

}
