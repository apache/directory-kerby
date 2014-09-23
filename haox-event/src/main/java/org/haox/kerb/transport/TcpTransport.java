package org.haox.kerb.transport;

import org.haox.kerb.message.Message;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;

public class TcpTransport extends Transport {

    private SocketChannel channel;

    public TcpTransport(SocketChannel channel, boolean isActive) throws IOException {
        super((InetSocketAddress) channel.getRemoteAddress(), isActive);
        this.channel = channel;
    }

    @Override
    protected void doSendMessage(Message message) {

    }
}
