package org.haox.event.network;

import org.haox.event.EventType;
import org.haox.transport.tcp.DecodingCallback;
import org.haox.transport.tcp.StreamingDecoder;

import java.nio.ByteBuffer;

public class TestNetworkBase {
    protected String serverHost = "127.0.0.1";
    protected short tcpPort = 8181;
    protected short udpPort = 8182;
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
