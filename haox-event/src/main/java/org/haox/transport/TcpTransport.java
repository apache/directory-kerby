package org.haox.transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public class TcpTransport extends Transport {

    private SocketChannel channel;

    public TcpTransport(SocketChannel channel, boolean isActive) throws IOException {
        super((InetSocketAddress) channel.getRemoteAddress(), isActive);
        this.channel = channel;
    }

    @Override
    protected void sendOutMessage(ByteBuffer message) {

    }
}
