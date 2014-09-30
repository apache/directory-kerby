package org.haox.transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

public class UdpTransport extends Transport {
    private DatagramChannel channel;

    public UdpTransport(DatagramChannel channel,
                        InetSocketAddress remoteAddress, boolean isActive) {
        super(remoteAddress, isActive);
        this.channel = channel;
    }

    public UdpTransport(DatagramChannel channel, InetSocketAddress remoteAddress) {
        this(channel, remoteAddress, true);
    }

    protected void onInboundMessage(ByteBuffer message) {
        handleInboundMessage(new Message(message));
    }

    @Override
    protected void sendOutMessage(Message message) throws IOException {
        ByteBuffer buffer = message.getContent();
        channel.send(buffer, getRemoteAddress());
    }
}
