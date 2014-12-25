package org.apache.haox.transport.buffer;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

public class BufferUtil {

    /**
     * Read len bytes from src buffer
     */
    public static ByteBuffer read(ByteBuffer src, int len) {
        if (len > src.remaining())
            throw new BufferOverflowException();

        ByteBuffer result = ByteBuffer.allocate(len);
        int n = src.remaining();
        for (int i = 0; i < n; i++) {
            result.put(src.get());
        }

        return result;
    }
}
