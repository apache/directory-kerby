package org.haox.transport.udp;

import org.haox.transport.Transport;
import org.haox.transport.buffer.TransBuffer;
import org.haox.transport.event.MessageEvent;
import org.haox.transport.event.TransportEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

public class UdpTransport extends Transport {
    private DatagramChannel channel;

    protected TransBuffer recvBuffer;

    public UdpTransport(DatagramChannel channel,
                        InetSocketAddress remoteAddress) {
        super(remoteAddress);
        this.channel = channel;
        this.recvBuffer = new TransBuffer();
    }

    protected void onRecvData(ByteBuffer data) {
        recvBuffer.write(data);
        dispatcher.dispatch(TransportEvent.createReadableTransportEvent(this));
    }

    @Override
    public void onReadable() throws IOException {
        super.onReadable();

        if (! recvBuffer.isEmpty()) {
            ByteBuffer message = recvBuffer.read();
            dispatcher.dispatch(MessageEvent.createInboundMessageEvent(this, message));
        }
    }

    @Override
    public void sendMessage(ByteBuffer message) {
        super.sendMessage(message);
        dispatcher.dispatch(TransportEvent.createWritableTransportEvent(this));
    }

    @Override
    protected void sendOutMessage(ByteBuffer message) throws IOException {
        channel.send(message, getRemoteAddress());
    }
}
