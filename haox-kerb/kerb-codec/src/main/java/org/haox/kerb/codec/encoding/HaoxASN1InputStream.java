package org.haox.kerb.codec.encoding;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.util.ASN1Dump;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;

public class HaoxASN1InputStream implements BERTags
{
    private ByteBuffer byteBuffer;
    private final int limit; // number of bytes that can be read from byteBuffer
    private final int offset;

    private int tag;
    private int tagNo;
    private int length;
    private boolean isConstructed;

    /**
     * Create an ASN1InputStream based on the input byte array. The length of DER objects in
     * the stream is automatically limited to the length of the input array.
     *
     * @param input array containing ASN.1 encoded data.
     */
    public HaoxASN1InputStream(byte[] input) {
        this(ByteBuffer.wrap(input), input.length);
    }

    public HaoxASN1InputStream(ByteBuffer buffer, int limit) {
        byteBuffer = buffer;
        this.limit = limit;
        this.offset = buffer.position();
    }

    public byte readByte() throws IOException {
        if (!available()) {
            throw new IOException("Buffer EOF");
        }
        return byteBuffer.get();
    }

    public ASN1Primitive readObject() throws IOException {
        return doReadObject(false);
    }

    public boolean available() {
        return byteBuffer.hasRemaining() &&
                byteBuffer.position() - offset < limit;
    }

    private ASN1Primitive doReadObject(boolean lazyLoad) throws IOException {
        if (! available()) {
            return null;
        }

        System.out.println("Reading object ...");
        //asn1Dump(fromByteBuffer(byteBuffer.duplicate(), limit), false);

        if (lazyLoad) byteBuffer.mark();

        readTag();
        isConstructed = (tag & CONSTRUCTED) != 0;

        // calculate length
        readLength();
        if (length < 0) { // indefinite length method
            throw new IOException("Unexpected length");
        }

        try {
            return buildObject(lazyLoad);
        } catch (IllegalArgumentException e) {
            throw new IOException("corrupted stream detected", e);
        } finally {
            int newPos = byteBuffer.position() + length;
            byteBuffer.position(newPos);
        }
    }

    /**
     * build an object given its tag and the number of bytes to construct it from.
     */
    private ASN1Primitive buildObject(boolean lazyLoad) throws IOException {
        if ((tag & APPLICATION) != 0) {
            return new HaoxDERApplicationSpecific(isConstructed, tagNo, byteBuffer.duplicate(), length);
        }

        if ((tag & TAGGED) != 0) {
            HaoxASN1InputStream ais = new HaoxASN1InputStream(byteBuffer.duplicate(), length);
            return ais.readTaggedObject(isConstructed, tagNo);
        }

        if (isConstructed) {
            switch (tagNo) {
                case OCTET_STRING:
                    // yes, people actually do this...
                    ASN1EncodableVector v = buildDEREncodableVector();
                    ASN1OctetString[] strings = new ASN1OctetString[v.size()];

                    for (int i = 0; i != strings.length; i++) {
                        strings[i] = (ASN1OctetString)v.get(i);
                    }

                    return new BEROctetString(strings);
                case SEQUENCE:
                    if (lazyLoad) {
                        ByteBuffer newByteBuffer = byteBuffer.duplicate();
                        newByteBuffer.reset();
                        int newLength = length;
                        // backwards to the starting point for this object
                        newLength += byteBuffer.position() - newByteBuffer.position();

                        return new HaoxLazyEncodedSequence(newByteBuffer, newLength);
                    } else {
                        return DERFactory.createSequence(buildDEREncodableVector());
                    }
                case SET:
                    return DERFactory.createSet(buildDEREncodableVector());
                case EXTERNAL:
                    return new DERExternal(buildDEREncodableVector());
                default:
                    throw new IOException("unknown tag " + tagNo + " encountered");
            }
        }

        return createPrimitiveDERObject(tagNo, byteBuffer.duplicate(), length);
    }

    ASN1EncodableVector buildDEREncodableVector() throws IOException {
        return new HaoxASN1InputStream(byteBuffer.duplicate(), length).readVector();
    }

    protected static char[] getBMPCharBuffer(ByteBuffer byteBuffer, int limit) throws IOException {
        int len = limit / 2;
        char[] buf = new char[len];
        int totalRead = 0;
        while (totalRead < len) {
            int ch1 = byteBuffer.get();
            if (ch1 < 0) {
                break;
            }
            int ch2 = byteBuffer.get();
            if (ch2 < 0) {
                break;
            }
            buf[totalRead++] = (char)((ch1 << 8) | (ch2 & 0xff));
        }

        return buf;
    }

    private void readTag() throws IOException {
        tag = readByte() & 0xff;
        if (tag <= 0) {
            if (tag == 0) {
                throw new IOException("unexpected end-of-contents marker");
            }
            return;
        }

        // calculate tag number
        tagNo = tag & 0x1f;

        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        if (tagNo == 0x1f) {
            tagNo = 0;

            int b = readByte() & 0xff;

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if ((b & 0x7f) == 0) {// Note: -1 will pass
                throw new IOException("corrupted stream - invalid high tag number found");
            }

            while ((b >= 0) && ((b & 0x80) != 0)) {
                tagNo |= (b & 0x7f);
                tagNo <<= 7;
                b = readByte();
            }

            if (b < 0) {
                throw new EOFException("EOF found inside tag value.");
            }

            tagNo |= (b & 0x7f);
        }
    }

    private void readLength() throws IOException {
        length = readByte() & 0xff;
        if (length < 0) {
            throw new EOFException("EOF found when length expected");
        }

        if (length == 0x80) {
            length = -1;      // indefinite-length encoding
        }

        if (length > 127) {
            int size = length & 0x7f;

            // Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be caught here
            if (size > 4) {
                throw new IOException("DER length more than 4 bytes: " + size);
            }

            length = 0;
            for (int i = 0; i < size; i++) {
                int next = readByte() & 0xff;

                if (next < 0) {
                    throw new EOFException("EOF found reading length");
                }

                length = (length << 8) + next;
            }

            if (length < 0) {
                throw new IOException("corrupted stream - negative length found");
            }
            if (length >= limit) {  // after all we must have read at least 1 byte
                throw new IOException("corrupted stream - out of bounds length found");
            }
        }
    }

    public static byte[] fromByteBuffer(ByteBuffer byteBuffer, int limit) {
        byte[] result = new byte[limit];
        byteBuffer.get(result);
        return result;
    }

    private static ASN1Primitive createPrimitiveDERObject(int tagNo, ByteBuffer byteBuffer, int limit) throws IOException {
        switch (tagNo) {
            case BIT_STRING:
                return DERBitString.fromInputStream(limit, new ByteArrayInputStream(fromByteBuffer(byteBuffer, limit)));
            case BMP_STRING:
                return new DERBMPString(new String(getBMPCharBuffer(byteBuffer, limit)));
            case BOOLEAN:
                return ASN1Boolean.fromOctetString(fromByteBuffer(byteBuffer, limit));
            case ENUMERATED:
                return ASN1Enumerated.fromOctetString(fromByteBuffer(byteBuffer, limit));
            case GENERALIZED_TIME:
                return new ASN1GeneralizedTime(fromByteBuffer(byteBuffer, limit));
            case GENERAL_STRING:
                return new DERGeneralString(fromByteBuffer(byteBuffer, limit));
            case IA5_STRING:
                return new DERIA5String(fromByteBuffer(byteBuffer, limit));
            case INTEGER:
                return new ASN1Integer(fromByteBuffer(byteBuffer, limit), false);
            case NULL:
                return DERNull.INSTANCE;   // actual content is ignored (enforce 0 length?)
            case NUMERIC_STRING:
                return new DERNumericString(fromByteBuffer(byteBuffer, limit));
            case OBJECT_IDENTIFIER:
                return ASN1ObjectIdentifier.fromOctetString(fromByteBuffer(byteBuffer, limit));
            case OCTET_STRING:
                return new DEROctetString(fromByteBuffer(byteBuffer, limit));
            case PRINTABLE_STRING:
                return new DERPrintableString(fromByteBuffer(byteBuffer, limit));
            case T61_STRING:
                return new DERT61String(fromByteBuffer(byteBuffer, limit));
            case UNIVERSAL_STRING:
                return new DERUniversalString(fromByteBuffer(byteBuffer, limit));
            case UTC_TIME:
                return new ASN1UTCTime(fromByteBuffer(byteBuffer, limit));
            case UTF8_STRING:
                return new DERUTF8String(fromByteBuffer(byteBuffer, limit));
            case VISIBLE_STRING:
                return new DERVisibleString(fromByteBuffer(byteBuffer, limit));
            default:
                throw new IOException("unknown tag " + tagNo + " encountered");
        }
    }

   private ASN1Primitive readTaggedObject(boolean constructed, int tagNo) throws IOException {
        if (!constructed) {
            // Note: !CONSTRUCTED => IMPLICIT
            throw new IOException("Implict not supported yet");
        }

        ASN1EncodableVector v = readVector();

        return v.size() == 1
                ?   new DERTaggedObject(true, tagNo, v.get(0))
                :   new DERTaggedObject(false, tagNo, DERFactory.createSequence(v));
    }

    private ASN1EncodableVector readVector() throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();

        ASN1Encodable obj;
        while ((obj = doReadObject(true)) != null) {
            v.add(obj.toASN1Primitive());
        }

        return v;
    }

    public static void asn1Dump(byte[] content, boolean verbose) throws IOException {
        ASN1InputStream ais = new ASN1InputStream(content, true);
        ASN1Object obj;
        while (null != (obj = ais.readObject())) {
            System.out.println(ASN1Dump.dumpAsString(obj, true));
        }
    }
}
