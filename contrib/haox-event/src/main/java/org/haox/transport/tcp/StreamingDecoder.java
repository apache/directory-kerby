package org.haox.transport.tcp;

import java.nio.ByteBuffer;

public interface StreamingDecoder {
    public void decode(ByteBuffer streamingBuffer, DecodingCallback callback);
}
