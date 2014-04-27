package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.LimitedByteBuffer;
import org.haox.asn1.TagClass;
import org.haox.asn1.TaggingOption;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;

public abstract class AbstractAsn1Type<T> implements Asn1Type {
    protected static int CONSTRUCTED_FLAG = 0x20;

    private int tagClass = -1;
    private int tagNo = -1;
    private T value;

    // for decoding
    private int tag = -1;
    private EncodingOption encodingOption = EncodingOption.UNKNOWN;
    private int encodingLen = -1;


    public AbstractAsn1Type(int tagClass, int tagNo) {
        this(tagClass, tagNo, null);
    }

    public AbstractAsn1Type(int tagClass, int tagNo, T value) {
        this.tagClass = tagClass;
        this.tagNo = tagNo;
        this.value = value;
    }

    public T getValue() {
        return value;
    }

    public void setValue(T value) {
        this.value = value;
    }

    @Override
    public int tagClass() {
        return tagClass;
    }

    @Override
    public int tagNo() {
        return tagNo;
    }

    protected int tag() {
        return tag;
    }

    @Override
    public byte[] encode(EncodingOption encodingOption) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(encodingLength(encodingOption));
        encode(byteBuffer, encodingOption);
        byteBuffer.flip();
        return byteBuffer.array();
    }

    @Override
    public void encode(ByteBuffer buffer, EncodingOption encodingOption) {
        encodeTag(buffer, makeTag(encodingOption));
        encodeLength(buffer, encodingBodyLength(encodingOption));
        encodeBody(buffer, encodingOption);
    }

    protected void encodeBody(ByteBuffer buffer, EncodingOption encodingOption) { }

    @Override
    public void decode(byte[] content) throws IOException {
        decode(new LimitedByteBuffer(content));
    }

    @Override
    public void decode(ByteBuffer content) throws IOException {
        decode(new LimitedByteBuffer(content));
    }

    protected int makeTag(EncodingOption encodingOption) {
        int flags = tagClass;
        if (isConstructed(encodingOption)) flags |= CONSTRUCTED_FLAG;
        int tag = flags | tagNo;
        return tag;
    }

    protected int encodingLength(EncodingOption encodingOption) {
        if (encodingOption != encodingOption || encodingLen == -1) {
            this.encodingOption = encodingOption;
            int bodyLen = encodingBodyLength(encodingOption);
            encodingLen = lengthOfTagLength(makeTag(encodingOption)) + lengthOfBodyLength(bodyLen) + bodyLen;
        }
        return encodingLen;
    }

    protected abstract boolean isConstructed(EncodingOption encodingOption);

    protected abstract int encodingBodyLength(EncodingOption encodingOption);

    protected void decode(LimitedByteBuffer content) throws IOException {
        int tag = readTag(content);
        int tagNo = readTagNo(content, tag);
        int length = readLength(content);

        decode(tag, tagNo, new LimitedByteBuffer(content, length));
    }

    protected void decode(int tag, int tagNo, LimitedByteBuffer content) throws IOException {
        if (this.tagClass != -1 && TagClass.fromValue(this.tagClass) != TagClass.fromTag(tag)) {
            throw new IOException("Unexpected tag class" + tag + ", expecting " + this.tagClass);
        }
        if (this.tagNo != -1 && this.tagNo != tagNo) {
            throw new IOException("Unexpected tagNo" + tagNo + ", expecting " + this.tagNo);
        }

        this.tagClass = TagClass.fromTag(tag).getValue();
        this.tag = tag;
        this.tagNo = tagNo;

        decodeBody(content);
    }

    protected abstract void decodeBody(LimitedByteBuffer content) throws IOException;

    protected int taggedEncodingLength(TaggingOption taggingOption, EncodingOption encodingOption) {
        int taggingTag = taggingOption.getTag(encodingOption);
        int taggingBodyLen = encodingLength(encodingOption);
        int taggingEncodingLen = lengthOfTagLength(taggingTag) + lengthOfBodyLength(taggingBodyLen) + taggingBodyLen;
        return taggingEncodingLen;
    }

    @Override
    public void taggedEncode(ByteBuffer buffer, TaggingOption taggingOption, EncodingOption encodingOption) {
        int taggingTag = taggingOption.getTag(encodingOption);
        buffer.put((byte) taggingTag);
        buffer.put((byte) encodingLength(encodingOption));
        encode(buffer, encodingOption);
    }

    @Override
    public void taggedDecode(ByteBuffer content, TaggingOption taggingOption) throws IOException {
        LimitedByteBuffer limitedBuffer = new LimitedByteBuffer(content);
        int taggingTag = readTag(limitedBuffer);
        int taggingTagNo = readTagNo(limitedBuffer, taggingTag);
        int taggingLength = readLength(limitedBuffer);

        decode(new LimitedByteBuffer(limitedBuffer, taggingLength));
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
        int tagNo = tag & 0x1f;
        int length = 1;

        if (tagNo >= 31) {
            if (tagNo < 128) {
                length++;
            } else {
                byte[] stack = new byte[5];
                int pos = stack.length;

                stack[--pos] = (byte)(tagNo & 0x7F);

                do {
                    tagNo >>= 7;
                    stack[--pos] = (byte)(tagNo & 0x7F | 0x80);
                }
                while (tagNo > 127);

                length += stack.length - pos;
            }
        }

        return length;
    }

    public static void encodeTag(ByteBuffer buffer, int tag) {
        int tagNo = tag & 0x1f;
        int flags = tag & 0xe0;
        if (tagNo < 31) {
            buffer.put((byte) tag);
        } else {
            buffer.put((byte) (flags | 0x1f));
            if (tagNo < 128) {
                buffer.put((byte) tagNo);
            } else {
                byte[] stack = new byte[5];
                int pos = stack.length;

                stack[--pos] = (byte)(tagNo & 0x7F);
                do {
                    tagNo >>= 7;
                    stack[--pos] = (byte)(tagNo & 0x7F | 0x80);
                }
                while (tagNo > 127);

                buffer.put(stack, pos, stack.length - pos);
            }
        }
    }

    public static void encodeLength(ByteBuffer buffer, int length) {
        if (length > 127) {
            int size = 1;
            int val = length;

            while ((val >>>= 8) != 0) {
                size++;
            }

            buffer.put((byte) (size | 0x80));

            for (int i = (size - 1) * 8; i >= 0; i -= 8) {
                buffer.put((byte) (length >> i));
            }
        }
        else {
            buffer.put((byte) length);
        }
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
            if (length > buffer.hasLeft()) {
                throw new IOException("Bad stream - out of bounds length found");
            }
        }

        return length;
    }
}
