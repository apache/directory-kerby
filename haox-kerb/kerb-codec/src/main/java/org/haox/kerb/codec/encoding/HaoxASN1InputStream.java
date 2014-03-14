package org.haox.kerb.codec.encoding;

import org.bouncycastle.asn1.*;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;

public class HaoxASN1InputStream implements BERTags
{
    private ByteBuffer byteBuffer;
    private final int limit; // number of bytes that can be read from byteBuffer
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
    }

    protected void readLength() throws IOException {
        this.length = readLength(byteBuffer, limit);
    }

    public byte read() {
        return byteBuffer.get();
    }

    public ASN1Primitive readObject() throws IOException {
        return doReadObject(false);
    }

    public ASN1Primitive doReadObject(boolean lazyLoad) throws IOException {
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
            byteBuffer.position(byteBuffer.position() + length);
        }
    }

    /**
     * build an object given its tag and the number of bytes to construct it from.
     */
    protected ASN1Primitive buildObject(boolean lazyLoad) throws IOException {
        if ((tag & APPLICATION) != 0) {
            return new HaoxDERApplicationSpecific(isConstructed, tagNo, byteBuffer.duplicate(), length);
        }

        if ((tag & TAGGED) != 0) {
            HaoxASN1InputStream ais = new HaoxASN1InputStream(byteBuffer.duplicate(), length);
            return ais.readTaggedObject(isConstructed, tagNo);
        }

        if (isConstructed) {
            // TODO There are other tags that may be constructed (e.g. BIT_STRING)
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

    ASN1EncodableVector buildEncodableVector()
            throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        ASN1Primitive o;

        while ((o = readObject()) != null)
        {
            v.add(o);
        }

        return v;
    }

    ASN1EncodableVector buildDEREncodableVector() throws IOException {
        return new HaoxASN1InputStream(byteBuffer, length).buildEncodableVector();
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
        tag = byteBuffer.get();
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

            int b = byteBuffer.get();

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if ((b & 0x7f) == 0) {// Note: -1 will pass
                throw new IOException("corrupted stream - invalid high tag number found");
            }

            while ((b >= 0) && ((b & 0x80) != 0)) {
                tagNo |= (b & 0x7f);
                tagNo <<= 7;
                b = byteBuffer.get();
            }

            if (b < 0) {
                throw new EOFException("EOF found inside tag value.");
            }

            tagNo |= (b & 0x7f);
        }
    }

    public static int readLength(ByteBuffer buffer, int limit) throws IOException {
        byte b = buffer.get();
        int length = b & 0xff;
        if (length < 0) {
            throw new EOFException("EOF found when length expected");
        }

        if (length == 0x80) {
            return -1;      // indefinite-length encoding
        }

        if (length > 127) {
            int size = length & 0x7f;

            // Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be caught here
            if (size > 4) {
                throw new IOException("DER length more than 4 bytes: " + size);
            }

            length = 0;
            for (int i = 0; i < size; i++) {
                int next = buffer.get();

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

        return length;
    }

    public static byte[] fromByteBuffer(ByteBuffer byteBuffer, int limit) {
        byte[] result = new byte[limit];
        byteBuffer.get(result);
        return result;
    }

    private static ASN1Primitive createPrimitiveDERObject(int tagNo, ByteBuffer byteBuffer, int limit) throws IOException {
        switch (tagNo) {
            case BIT_STRING:
                return DERBitString.fromByteArray(fromByteBuffer(byteBuffer, limit));
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

   private ASN1Primitive readTaggedObject(boolean constructed, int tag) throws IOException {
        if (!constructed) {
            // Note: !CONSTRUCTED => IMPLICIT
            throw new IOException("Implict not supported yet");
        }

        ASN1EncodableVector v = readVector();

        return v.size() == 1
                ?   new DERTaggedObject(true, tag, v.get(0))
                :   new DERTaggedObject(false, tag, DERFactory.createSequence(v));
    }

    private ASN1EncodableVector readVector() throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();

        ASN1Encodable obj;
        while ((obj = doReadObject(true)) != null) {
            v.add(obj.toASN1Primitive());
        }

        return v;
    }

    /*
    public ASN1Encodable parser_readObject()
            throws IOException
    {
        int tag = read();
        if (tag == -1)
        {
            return null;
        }

        //
        // calculate tag number
        //
        int tagNo = readTagNumber(this, tag);

        boolean isConstructed = (tag & BERTags.CONSTRUCTED) != 0;

        //
        // calculate length
        //
        int length = readLength(this, limit);

        if (length < 0) // indefinite length method
        {
            if (!isConstructed)
            {
                throw new IOException("indefinite length primitive encoding encountered");
            }

            IndefiniteLengthInputStream indIn = new IndefiniteLengthInputStream(_in, _limit);
            ASN1StreamParser sp = new ASN1StreamParser(indIn, _limit);

            if ((tag & BERTags.APPLICATION) != 0)
            {
                return new BERApplicationSpecificParser(tagNo, sp);
            }

            if ((tag & BERTags.TAGGED) != 0)
            {
                return new BERTaggedObjectParser(true, tagNo, sp);
            }

            return sp.readIndef(tagNo);
        }
        else
        {
            org.bouncycastle.asn1.DefiniteLengthInputStream defIn = new org.bouncycastle.asn1.DefiniteLengthInputStream(_in, length);

            if ((tag & BERTags.APPLICATION) != 0)
            {
                return new DERApplicationSpecific(isConstructed, tagNo, defIn.toByteArray());
            }

            if ((tag & BERTags.TAGGED) != 0)
            {
                return new BERTaggedObjectParser(isConstructed, tagNo, new ASN1StreamParser(defIn));
            }

            if (isConstructed)
            {
                // TODO There are other tags that may be constructed (e.g. BIT_STRING)
                switch (tagNo)
                {
                    case BERTags.OCTET_STRING:
                        //
                        // yes, people actually do this...
                        //
                        return new BEROctetStringParser(new ASN1StreamParser(defIn));
                    case BERTags.SEQUENCE:
                        return new DERSequenceParser(new ASN1StreamParser(defIn));
                    case BERTags.SET:
                        return new DERSetParser(new ASN1StreamParser(defIn));
                    case BERTags.EXTERNAL:
                        return new DERExternalParser(new ASN1StreamParser(defIn));
                    default:
                        throw new IOException("unknown tag " + tagNo + " encountered");
                }
            }

            // Some primitive encodings can be handled by parsers too...
            switch (tagNo)
            {
                case BERTags.OCTET_STRING:
                    return new DEROctetStringParser(defIn);
            }

            try
            {
                return ASN1InputStream.createPrimitiveDERObject(tagNo, defIn, tmpBuffers);
            }
            catch (IllegalArgumentException e)
            {
                throw new ASN1Exception("corrupted stream detected", e);
            }
        }
    } */

}
