package org.haox.message;

import java.nio.ByteBuffer;

public class Message {

    private ByteBuffer[] buffers;

    public Message(ByteBuffer ... contents) {
        this.buffers = contents;
    }

    public ByteBuffer[] getContents() {
        return this.buffers;
    }

    public ByteBuffer getContent() {
        if (buffers.length > 0) {
            return buffers[0];
        }
        return null;
    }
}
