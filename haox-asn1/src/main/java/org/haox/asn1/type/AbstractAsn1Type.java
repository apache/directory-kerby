package org.haox.asn1.type;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;

public abstract class AbstractAsn1Type<T> implements Asn1Type {
    private final int tag;
    private int encodingLen = -1;
    private T value;

    public AbstractAsn1Type(int tag) {
        this(tag, null);
    }

    public AbstractAsn1Type(int tag, T value) {
        this.tag = tag;
        this.value = value;
    }

    public T getValue() {
        return value;
    }

    public void setValue(T value) {
        this.value = value;
    }

    @Override
    public int tag() {
        return tag;
    }

    @Override
    public byte[] encode() {
        ByteBuffer byteBuffer = ByteBuffer.allocate(encodingLength());
        encode(byteBuffer);
        byteBuffer.flip();
        return byteBuffer.array();
    }

    @Override
    public void decode(byte[] content) throws IOException {
        decode(new LimitedByteBuffer(content));
    }

    @Override
    public int encodingLength() {
        if (encodingLen == -1) {
            int bodyLen = bodyLength();
            encodingLen = lengthOfTagLength(tag()) + lengthOfBodyLength(bodyLen) + bodyLen;
        }
        return encodingLen;
    }

    protected abstract int bodyLength();

    @Override
    public void decode(LimitedByteBuffer content) throws IOException {
        int tag = readTag(content);
        int tagNo = readTagNo(content, tag);
        int length = readLength(content);

        decode(tag, tagNo, new LimitedByteBuffer(content, length));
    }

    @Override
    public void decode(int tag, int tagNo, LimitedByteBuffer content) throws IOException {
        if (this.tag != -1 && this.tag != tag) {
            throw new IOException("Unexpected tag " + tag + ", expecting " + this.tag);
        }
        decodeValue(content);
    }

    protected abstract void decodeValue(LimitedByteBuffer content) throws IOException;

    protected boolean isConstructed() {
        return true;
    }

    public static int lengthOfBodyLength(int length) {
        int count = 1;

        if (length > 127) {
            int size = 1;
            int val = length;

            while ((val >>>= 8) != 0) {
                size++;
            }

            for (int i = (size - 1) * 8; i >= 0; i -= 8) {
                count++;
            }
        }

        return count;
    }

    public static int lengthOfTagLength(int tag) {
        int length = 1;

        if (tag >= 31) {
            if (tag < 128) {
                length++;
            } else {
                byte[] stack = new byte[5];
                int pos = stack.length;

                stack[--pos] = (byte)(tag & 0x7F);

                do {
                    tag >>= 7;
                    stack[--pos] = (byte)(tag & 0x7F | 0x80);
                }
                while (tag > 127);

                length += stack.length - pos;
            }
        }

        return length;
    }

    public static int readTag(LimitedByteBuffer buffer) throws IOException {
        int tag = buffer.readByte() & 0xff;
        if (tag <= 0) {
            if (tag == 0) {
                throw new IOException("Unexpected EOF");
            }
        }
        return tag;
    }

    public static int readTagNo(LimitedByteBuffer buffer, int tag) throws IOException {
        int tagNo = tag & 0x1f;

        if (tagNo == 0x1f) {
            tagNo = 0;

            int b = buffer.readByte() & 0xff;
            if ((b & 0x7f) == 0) {
                throw new IOException("Bad stream - invalid high tag number found");
            }

            while ((b >= 0) && ((b & 0x80) != 0)) {
                tagNo |= (b & 0x7f);
                tagNo <<= 7;
                b = buffer.readByte();
            }

            if (b < 0) {
                throw new EOFException("Unexpected EOF");
            }

            tagNo |= (b & 0x7f);
        }

        return tagNo;
    }

    public static int readLength(LimitedByteBuffer buffer) throws IOException {
        int length = buffer.readByte() & 0xff;
        if (length < 0) {
            throw new EOFException("Unexpected EOF");
        }

        if (length == 0x80) {
            length = -1;
        }

        if (length > 127) {
            int size = length & 0x7f;
            if (size > 4) {
                throw new IOException("DER length more than 4 bytes: " + size);
            }

            length = 0;
            for (int i = 0; i < size; i++) {
                int next = buffer.readByte() & 0xff;

                if (next < 0) {
                    throw new EOFException("Unexpected EOF");
                }

                length = (length << 8) + next;
            }

            if (length < 0) {
                throw new IOException("Bad stream - negative length found");
            }
            if (length >= buffer.hasLeft()) {
                throw new IOException("Bad stream - out of bounds length found");
            }
        }

        return length;
    }
}
