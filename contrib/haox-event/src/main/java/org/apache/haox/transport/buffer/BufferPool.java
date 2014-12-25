package org.apache.haox.transport.buffer;

import java.nio.ByteBuffer;

public class BufferPool {

    public static ByteBuffer allocate(int len) {
        return ByteBuffer.allocate(len);
    }

    public static void release(ByteBuffer buffer) {

    }
}
