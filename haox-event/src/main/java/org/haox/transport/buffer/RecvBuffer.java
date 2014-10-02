package org.haox.transport.buffer;

public abstract class RecvBuffer {

    private byte[] buffer;
    private int rIndex;
    private int wIndex;

    private int rMark;
    private int wMark;

    public RecvBuffer() {
        this(512);
    }

    public RecvBuffer(int initialCapacity) {
        buffer = new byte[initialCapacity];
    }

    public byte readByte() {
        checkRead(1);

        return buffer[rIndex ++];
    }

    public Short readShort() {
        checkRead(2);

        return null;//buffer[rIndex ++];
    }

    protected void checkRead(int toRead) {
        if (rIndex + toRead >= buffer.length) {
            throw new IndexOutOfBoundsException();
        }
    }
}
