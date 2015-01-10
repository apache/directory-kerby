package org.apache.haox.event.network;

import org.apache.haox.event.EventType;
import org.apache.haox.transport.tcp.DecodingCallback;
import org.apache.haox.transport.tcp.StreamingDecoder;

import java.nio.ByteBuffer;

public class TestNetworkBase {
    protected String serverHost = "127.0.0.1";
    protected short tcpPort = 8183;
    protected short udpPort = 8184;
    protected String TEST_MESSAGE = "Hello world!";
    protected String clientRecvedMessage;

    protected enum TestEventType implements EventType {
        FINISHED
    }

    protected String recvBuffer2String(ByteBuffer buffer) {
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        return new String(bytes);
    }

    protected StreamingDecoder createStreamingDecoder() {
        return new StreamingDecoder() {
            @Override
            public void decode(ByteBuffer streamingBuffer, DecodingCallback callback) {
                int expectedMessageLength = TEST_MESSAGE.getBytes().length;
                if (streamingBuffer.remaining() >= expectedMessageLength) {
                    callback.onMessageComplete(expectedMessageLength);
                } else {
                    callback.onMoreDataNeeded(expectedMessageLength);
                }
            }
        };
    }
}
