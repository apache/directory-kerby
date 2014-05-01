package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.LimitedByteBuffer;
import org.haox.asn1.TagClass;
import org.haox.asn1.TaggingOption;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;

public abstract class AbstractAsn1Type<T> implements Asn1Type {
    private TagClass tagClass = TagClass.UNKNOWN;
    private int tagNo = -1;
    private T value;

    // for decoding
    private int tag = -1;
    protected EncodingOption encodingOption = EncodingOption.UNKNOWN;
    private int encodingLen = -1;


    public AbstractAsn1Type(TagClass tagClass, int tagNo) {
        this(tagClass, tagNo, null);
    }

    public AbstractAsn1Type(TagClass tagClass, int tagNo, T value) {
        this.tagClass = tagClass;
        this.tagNo = tagNo;
        this.value = value;
    }

    public void setEncodingOption(EncodingOption encodingOption) {
        this.encodingOption = encodingOption;
    }

    public T getValue() {
        return value;
    }

    public void setValue(T value) {
        this.value = value;
    }

    @Override
    public TagClass tagClass() {
        return tagClass;
    }

    @Override
    public int tagNo() {
        return tagNo;
    }

    @Override
    public int tag() {
        if (tag == -1) {
            tag = makeTag();
        }
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
    public void encode(ByteBuffer buffer) {
        encodeTag(buffer, makeTag());
        encodeLength(buffer, encodingBodyLength());
        encodeBody(buffer);
    }

    protected void encodeBody(ByteBuffer buffer) { }

    @Override
    public void decode(byte[] content) throws IOException {
        decode(new LimitedByteBuffer(content));
    }

    @Override
    public void decode(ByteBuffer content) throws IOException {
        decode(new LimitedByteBuffer(content));
    }

    protected int makeTag() {
        int flags = tagClass.getValue();
        if (isConstructed()) flags |= EncodingOption.CONSTRUCTED_FLAG;
        int tag = flags | tagNo;
        return tag;
    }

    protected int encodingLength() {
        if (encodingLen == -1) {
            int bodyLen = encodingBodyLength();
            encodingLen = lengthOfTagLength(makeTag()) + lengthOfBodyLength(bodyLen) + bodyLen;
        }
        return encodingLen;
    }

    protected abstract boolean isConstructed();

    protected abstract int encodingBodyLength();

    protected void decode(LimitedByteBuffer content) throws IOException {
        int tag = readTag(content);
        int tagNo = readTagNo(content, tag);
        int length = readLength(content);

        decode(tag, tagNo, new LimitedByteBuffer(content, length));
    }

    protected void decode(int tag, int tagNo, LimitedByteBuffer content) throws IOException {
        if (this.tagClass != TagClass.UNKNOWN && this.tagClass != TagClass.fromTag(tag)) {
            throw new IOException("Unexpected tag " + tag + ", expecting " + this.tagClass);
        }
        if (this.tagNo != -1 && this.tagNo != tagNo) {
            throw new IOException("Unexpected tagNo " + tagNo + ", expecting " + this.tagNo);
        }

        this.tagClass = TagClass.fromTag(tag);
        this.tag = tag;
        this.tagNo = tagNo;

        decodeBody(content);
    }

    protected abstract void decodeBody(LimitedByteBuffer content) throws IOException;

    protected int taggedEncodingLength(TaggingOption taggingOption) {
        int taggingTag = taggingOption.makeTag(isConstructed());
        int taggingBodyLen = taggingOption.isImplicit() ? encodingBodyLength() : encodingLength();
        int taggingEncodingLen = lengthOfTagLength(taggingTag) + lengthOfBodyLength(taggingBodyLen) + taggingBodyLen;
        return taggingEncodingLen;
    }

    public byte[] taggedEncode(TaggingOption taggingOption) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(taggedEncodingLength(taggingOption));
        taggedEncode(byteBuffer, taggingOption);
        byteBuffer.flip();
        return byteBuffer.array();
    }

    @Override
    public void taggedEncode(ByteBuffer buffer, TaggingOption taggingOption) {
        int taggingTag = taggingOption.makeTag(isConstructed());
        encodeTag(buffer, taggingTag);
        int taggingBodyLen = taggingOption.isImplicit() ? encodingBodyLength() : encodingLength();
        encodeLength(buffer, taggingBodyLen);
        if (taggingOption.isImplicit()) {
            encodeBody(buffer);
        } else {
            encode(buffer);
        }
    }

    public void taggedDecode(byte[] content, TaggingOption taggingOption) throws IOException {
        taggedDecode(ByteBuffer.wrap(content), taggingOption);
    }

    @Override
    public void taggedDecode(ByteBuffer content, TaggingOption taggingOption) throws IOException {
        LimitedByteBuffer limitedBuffer = new LimitedByteBuffer(content);
        taggedDecode(limitedBuffer, taggingOption);
    }

    protected void taggedDecode(LimitedByteBuffer content, TaggingOption taggingOption) throws IOException {
        int taggingTag = readTag(content);
        int taggingTagNo = readTagNo(content, taggingTag);
        int taggingLength = readLength(content);
        LimitedByteBuffer newContent = new LimitedByteBuffer(content, taggingLength);

        taggedDecode(taggingTag, taggingTagNo, newContent, taggingOption);
    }

    protected void taggedDecode(int taggingTag, int taggingTagNo, LimitedByteBuffer content, TaggingOption taggingOption) throws IOException {
        int expectedTaggingTag = taggingOption.makeTag(isConstructed());
        if (expectedTaggingTag != taggingTag) {
            throw new IOException("Unexpected tag " + taggingTag + ", expecting " + expectedTaggingTag);
        }
        if (taggingOption.getTagNo() != taggingTagNo) {
            throw new IOException("Unexpected tagNo " + taggingTagNo + ", expecting " + taggingOption.getTagNo());
        }

        if (taggingOption.isImplicit()) {
            decodeBody(content);
        } else {
            decode(content);
        }
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
