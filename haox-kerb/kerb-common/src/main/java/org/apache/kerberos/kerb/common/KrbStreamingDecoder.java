package org.apache.kerberos.kerb.common;

import org.apache.haox.transport.tcp.DecodingCallback;
import org.apache.haox.transport.tcp.StreamingDecoder;

import java.nio.ByteBuffer;

public class KrbStreamingDecoder implements StreamingDecoder {

    @Override
    public void decode(ByteBuffer streamingBuffer, DecodingCallback callback) {
        if (streamingBuffer.remaining() >= 4) {
            int len = streamingBuffer.getInt();
            if (streamingBuffer.remaining() >= len) {
                callback.onMessageComplete(len + 4);
            } else {
                callback.onMoreDataNeeded(len + 4);
            }
        } else {
            callback.onMoreDataNeeded();
        }
    }
}
