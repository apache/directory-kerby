package org.haox.transport.buffer;

import org.haox.transport.BytesUtil;

public abstract class RecvBuffer {

    private byte[] buffer;
    private int rIndex;
    private int wIndex;

    private int rMark;
    private int wMark;

    public RecvBuffer() {
        this(512);
    }

    public RecvBuffer(int capacity) {
        buffer = new byte[capacity];
    }

    public byte readByte() {
        checkRead(1);

        return buffer[rIndex ++];
    }

    public short readShort() {
        checkRead(2);

        short val = BytesUtil.bytes2short(buffer, rIndex, true);
        rIndex += 2;

        return val;
    }

    public int readInt() {
        checkRead(4);

        int val = BytesUtil.bytes2int(buffer, rIndex, true);
        rIndex += 4;

        return val;
    }

    public byte[] readBytes(int len) {
        checkRead(len);

        byte[] result = BytesUtil.duplicate(buffer, rIndex, len);
        rIndex += len;

        return result;
    }

    public void writeByte(byte aByte) {
        checkWrite(1);

        buffer[wIndex ++] = aByte;
    }

    public void writeShort(short val) {
        checkWrite(2);

        BytesUtil.short2bytes(val, buffer, wIndex, true);
        wIndex += 2;
    }

    public void writeInt(int val) {
        checkWrite(4);

        BytesUtil.int2bytes(val, buffer, wIndex, true);
        wIndex += 4;
    }

    public void writeBytes(byte[] bytes) {
        checkWrite(bytes.length);

        System.arraycopy(bytes, 0, buffer, wIndex, bytes.length);
        wIndex += bytes.length;
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
        if (wIndex + toWrite >= buffer.length) {
            throw new IndexOutOfBoundsException();
        }
    }
}
