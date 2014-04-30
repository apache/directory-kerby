package org.haox.asn1;

import java.io.IOException;
import java.nio.ByteBuffer;

public class LimitedByteBuffer {
    private final ByteBuffer byteBuffer;
    private final int limit;
    private int startOffset;

    public LimitedByteBuffer(byte[] bytes) {
        this.byteBuffer = ByteBuffer.wrap(bytes);
        this.limit = bytes.length;
        this.startOffset = 0;
    }

    public LimitedByteBuffer(ByteBuffer byteBuffer) {
        this(byteBuffer, byteBuffer.limit());
    }

    public LimitedByteBuffer(ByteBuffer byteBuffer, int limit) {
        this.byteBuffer = byteBuffer;
        this.limit = limit;
        this.startOffset = byteBuffer.position();
    }

    public LimitedByteBuffer(LimitedByteBuffer other, int limit) {
        if (limit > other.hasLeft()) {
            throw new IllegalArgumentException("limit is too large, out of bound");
        }
        this.byteBuffer = other.byteBuffer.duplicate();
        this.limit = limit;
        this.startOffset = byteBuffer.position();
    }

    public boolean available() {
        return byteBuffer.hasRemaining() &&
                byteBuffer.position() - startOffset < limit;
    }

    public long hasRead() {
        return byteBuffer.position() - startOffset;
    }
    public long hasLeft() {
        return limit - hasRead();
    }

    public byte readByte() throws IOException {
        if (!available()) {
            throw new IOException("Buffer EOF");
        }
        return byteBuffer.get();
    }

    public byte[] readAllLeftBytes() throws IOException {
        return readBytes((int) hasLeft());
    }

    public void skip(int len) throws IOException {
        checkLen(len);
        int newPos = byteBuffer.position() + len;
        byteBuffer.position(newPos);
    }

    public byte[] readBytes(int len) throws IOException {
        checkLen(len);

        byte[] bytes = new byte[len];
        byteBuffer.get(bytes);
        return bytes;
    }

    private void checkLen(int len) throws IOException {
        if (len <= 0) {
            throw new IllegalArgumentException("Bad argument len: " + len);
        }
        if (!available()) {
            throw new IOException("Buffer EOF");
        }
        if (hasLeft() < len) {
            throw new IOException("Out of Buffer");
        }
    }

    public void readBytes(byte[] bytes) throws IOException {
        if (bytes == null) {
            throw new IllegalArgumentException("Bad argument bytes: null");
        }
        if (!available()) {
            throw new IOException("Buffer EOF");
        }
        if (hasLeft() < bytes.length) {
            throw new IOException("Out of Buffer");
        }

        byteBuffer.get(bytes);
    }
}
