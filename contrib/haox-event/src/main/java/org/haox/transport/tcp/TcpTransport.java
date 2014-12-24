package org.haox.transport.tcp;

import org.haox.transport.Transport;
import org.haox.transport.buffer.BufferPool;
import org.haox.transport.buffer.RecvBuffer;
import org.haox.transport.event.MessageEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

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
        ByteBuffer writeBuffer = BufferPool.allocate(65536);
        if (channel.read(writeBuffer) <= 0) {
            BufferPool.release(writeBuffer);
            return;
        }

        writeBuffer.flip();
        recvBuffer.write(writeBuffer);

        WithReadDataHander rdHandler = new WithReadDataHander();
        rdHandler.handle();
    }

    class WithReadDataHander implements DecodingCallback {
        private ByteBuffer streamingBuffer;

        @Override
        public void onMessageComplete(int messageLength) {
            ByteBuffer message = null;

            int remaining = streamingBuffer.remaining();
            if (remaining == messageLength) {
                message = streamingBuffer;
            } else if (remaining > messageLength) {
                message = streamingBuffer.duplicate();
                int newLimit = streamingBuffer.position() + messageLength;
                message.limit(newLimit);

                streamingBuffer.position(newLimit);
                recvBuffer.writeFirst(streamingBuffer);
            }

            if (message != null) {
                dispatcher.dispatch(MessageEvent.createInboundMessageEvent(TcpTransport.this, message));
            }
        }

        @Override
        public void onMoreDataNeeded() {
            recvBuffer.writeFirst(streamingBuffer);
        }

        @Override
        public void onMoreDataNeeded(int needDataLength) {
            recvBuffer.writeFirst(streamingBuffer);
        }

        public void handle() {
            if (recvBuffer.isEmpty()) return;

            streamingBuffer = recvBuffer.readMostBytes();

            streamingDecoder.decode(streamingBuffer.duplicate(), this);
        }
    }
}
