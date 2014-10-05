package org.haox.transport.tcp;

import org.haox.transport.Transport;
import org.haox.transport.buffer.RecvBuffer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class TcpTransport extends Transport {

    private SocketChannel channel;

    private StreamingDecoder streamingDecoder;

    private RecvBuffer recvBuffer;

    public TcpTransport(SocketChannel channel,
                        StreamingDecoder streamingDecoder) throws IOException {
        super((InetSocketAddress) channel.getRemoteAddress());
        this.channel = channel;
        this.streamingDecoder = streamingDecoder;

        this.recvBuffer = new RecvBuffer();
    }

    @Override
    protected void sendOutMessage(ByteBuffer message) throws IOException {
        channel.write(message);
    }

    public void onReadable() throws IOException {
        ByteBuffer writeBuffer = recvBuffer.getWriteBuffer();
        StreamingDecoder.DecodingResult result;
        if (channel.read(writeBuffer) > 0) {
            result = streamingDecoder.decode(writeBuffer);
            if (result instanceof StreamingDecoder.MessageResult) {
                ByteBuffer message = null;//recvBuffer.read()
            }
        }
    }
}
