package org.haox.kerb.message;

import java.nio.ByteBuffer;

public class Message {

    private ByteBuffer[] buffers;

    public Message(ByteBuffer ... contents) {
        this.buffers = contents;
    }

    public ByteBuffer[] getContents() {
        return this.buffers;
    }
}
