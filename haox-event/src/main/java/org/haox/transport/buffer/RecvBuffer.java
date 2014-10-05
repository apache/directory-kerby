package org.haox.transport.buffer;

import java.nio.ByteBuffer;

public class RecvBuffer {

    private byte[] buffer;
    private int capacity;
    private int rIndex;
    private int wIndex;

    private int rMark;
    private int wMark;

    public RecvBuffer() {
        this(512);
    }

    public RecvBuffer(int capacity) {
        this.capacity = capacity;
        buffer = new byte[capacity];
    }

    public ByteBuffer getReadBuffer() {
        ByteBuffer byteBuffer = ByteBuffer.wrap(buffer, rIndex, wIndex);
        return byteBuffer;
    }

    public void setReadPosition(int position) {
        rIndex = position;
    }

    public ByteBuffer getWriteBuffer() {
        ByteBuffer byteBuffer = ByteBuffer.wrap(buffer, wIndex, capacity);
        return byteBuffer;
    }

    public void setWritePosition(int position) {
        wIndex = position;
    }

    public int readable() {
        return wIndex - rIndex;
    }

    public int writable() {
        return buffer.length - wIndex;
    }

    public int discardable() {
        return rIndex;
    }

    public void mark() {
        rMark = rIndex;
        wMark = wIndex;
    }

    public void restore() {
        rIndex = rMark;
        wIndex = wMark;
    }

    public void reset() {
        rIndex = rMark = 0;
        wIndex = wMark = 0;
    }

    protected void checkRead(int toRead) {
        if (rIndex + toRead >= wIndex) {
            throw new IndexOutOfBoundsException();
        }
    }

    protected void checkWrite(int toWrite) {
        if (wIndex + toWrite >= capacity) {
            throw new IndexOutOfBoundsException();
        }
    }
}
