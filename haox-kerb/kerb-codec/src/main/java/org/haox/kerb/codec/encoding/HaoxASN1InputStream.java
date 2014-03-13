package org.haox.kerb.codec.encoding;

import org.bouncycastle.asn1.*;
import org.bouncycastle.util.io.Streams;

import java.io.*;

public class HaoxASN1InputStream extends FilterInputStream implements BERTags
{
    private final int limit;

    public HaoxASN1InputStream(
            InputStream is)
    {
        this(is, StreamUtil.findLimit(is));
    }

    /**
     * Create an ASN1InputStream based on the input byte array. The length of DER objects in
     * the stream is automatically limited to the length of the input array.
     *
     * @param input array containing ASN.1 encoded data.
     */
    public HaoxASN1InputStream(
            byte[] input)
    {
        this(new ByteArrayInputStream(input), input.length);
    }

    /**
     * Create an ASN1InputStream where no DER object will be longer than limit.
     *
     * @param input stream containing ASN.1 encoded data.
     * @param limit maximum size of a DER encoded object.
     */
    public HaoxASN1InputStream(
            InputStream input,
            int         limit)
    {
        super(input);
        this.limit = limit;
    }

    int getLimit()
    {
        return limit;
    }

    protected int readLength()
            throws IOException
    {
        return readLength(this, limit);
    }

    protected void readFully(
            byte[]  bytes)
            throws IOException
    {
        if (Streams.readFully(this, bytes) != bytes.length)
        {
            throw new EOFException("EOF encountered in middle of object");
        }
    }

    /**
     * build an object given its tag and the number of bytes to construct it from.
     */
    protected ASN1Primitive buildObject(int tag, int tagNo, int length, boolean lazyLoad) throws IOException {
        boolean isConstructed = (tag & CONSTRUCTED) != 0;

        DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(this, length);

        if ((tag & APPLICATION) != 0) {
            return new DERApplicationSpecific(isConstructed, tagNo, defIn.toByteArray());
        }

        if ((tag & TAGGED) != 0) {
            //throw new IOException("TAGGED not implemented yet");
            HaoxASN1InputStream ais = new HaoxASN1InputStream(defIn);
            return ais.readTaggedObject(defIn, isConstructed, tagNo);
        }

        if (isConstructed) {
            // TODO There are other tags that may be constructed (e.g. BIT_STRING)
            switch (tagNo) {
                case OCTET_STRING:
                    //
                    // yes, people actually do this...
                    //
                    ASN1EncodableVector v = buildDEREncodableVector(defIn);
                    ASN1OctetString[] strings = new ASN1OctetString[v.size()];

                    for (int i = 0; i != strings.length; i++) {
                        strings[i] = (ASN1OctetString)v.get(i);
                    }

                    return new BEROctetString(strings);
                case SEQUENCE:
                    if (lazyLoad) {
                        this.reset();
                        DefiniteLengthInputStream defIn2 = new DefiniteLengthInputStream(this, getLimit());
                        return new HaoxLazyEncodedSequence(defIn2.toByteArray());
                    } else {
                        return DERFactory.createSequence(buildDEREncodableVector(defIn));
                    }
                case SET:
                    return DERFactory.createSet(buildDEREncodableVector(defIn));
                case EXTERNAL:
                    return new DERExternal(buildDEREncodableVector(defIn));
                default:
                    throw new IOException("unknown tag " + tagNo + " encountered");
            }
        }

        return createPrimitiveDERObject(tagNo, defIn);
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

    ASN1EncodableVector buildDEREncodableVector(
            DefiniteLengthInputStream dIn) throws IOException
    {
        return new HaoxASN1InputStream(dIn).buildEncodableVector();
    }

    public ASN1Primitive readObject() throws IOException {
        return doReadObject(false);
    }

    public ASN1Primitive doReadObject(boolean lazyLoad) throws IOException {
        if (lazyLoad) this.mark(getLimit());

        int tag = read();
        if (tag <= 0) {
            if (tag == 0) {
                throw new IOException("unexpected end-of-contents marker");
            }

            return null;
        }

        //
        // calculate tag number
        //
        int tagNo = readTagNumber(this, tag);

        boolean isConstructed = (tag & CONSTRUCTED) != 0;

        //
        // calculate length
        //
        int length = readLength();

        if (length < 0) { // indefinite length method
            throw new IOException("Unexpected length");
        }

        try {
            return buildObject(tag, tagNo, length, lazyLoad);
        } catch (IllegalArgumentException e) {
            throw new IOException("corrupted stream detected", e);
        }
    }

    private static char[] getBMPCharBuffer(DefiniteLengthInputStream defIn)
            throws IOException
    {
        int len = defIn.getRemaining() / 2;
        char[] buf = new char[len];
        int totalRead = 0;
        while (totalRead < len)
        {
            int ch1 = defIn.read();
            if (ch1 < 0)
            {
                break;
            }
            int ch2 = defIn.read();
            if (ch2 < 0)
            {
                break;
            }
            buf[totalRead++] = (char)((ch1 << 8) | (ch2 & 0xff));
        }

        return buf;
    }

    protected static int readTagNumber(InputStream s, int tag)
            throws IOException
    {
        int tagNo = tag & 0x1f;

        //
        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        //
        if (tagNo == 0x1f)
        {
            tagNo = 0;

            int b = s.read();

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if ((b & 0x7f) == 0) // Note: -1 will pass
            {
                throw new IOException("corrupted stream - invalid high tag number found");
            }

            while ((b >= 0) && ((b & 0x80) != 0))
            {
                tagNo |= (b & 0x7f);
                tagNo <<= 7;
                b = s.read();
            }

            if (b < 0)
            {
                throw new EOFException("EOF found inside tag value.");
            }

            tagNo |= (b & 0x7f);
        }

        return tagNo;
    }

    static int readLength(InputStream s, int limit)
            throws IOException
    {
        int length = s.read();
        if (length < 0)
        {
            throw new EOFException("EOF found when length expected");
        }

        if (length == 0x80)
        {
            return -1;      // indefinite-length encoding
        }

        if (length > 127)
        {
            int size = length & 0x7f;

            // Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be caught here
            if (size > 4)
            {
                throw new IOException("DER length more than 4 bytes: " + size);
            }

            length = 0;
            for (int i = 0; i < size; i++)
            {
                int next = s.read();

                if (next < 0)
                {
                    throw new EOFException("EOF found reading length");
                }

                length = (length << 8) + next;
            }

            if (length < 0)
            {
                throw new IOException("corrupted stream - negative length found");
            }

            if (length >= limit)   // after all we must have read at least 1 byte
            {
                throw new IOException("corrupted stream - out of bounds length found");
            }
        }

        return length;
    }

    protected static ASN1Primitive createPrimitiveDERObject(
            int tagNo, DefiniteLengthInputStream defIn) throws IOException {
        switch (tagNo) {
            case BIT_STRING:
                return DERBitString.fromInputStream(defIn.getRemaining(), defIn);
            case BMP_STRING:
                return new DERBMPString(new String(getBMPCharBuffer(defIn)));
            case BOOLEAN:
                return ASN1Boolean.fromOctetString(defIn.toByteArray());
            case ENUMERATED:
                return ASN1Enumerated.fromOctetString(defIn.toByteArray());
            case GENERALIZED_TIME:
                return new ASN1GeneralizedTime(defIn.toByteArray());
            case GENERAL_STRING:
                return new DERGeneralString(defIn.toByteArray());
            case IA5_STRING:
                return new DERIA5String(defIn.toByteArray());
            case INTEGER:
                return new ASN1Integer(defIn.toByteArray(), false);
            case NULL:
                return DERNull.INSTANCE;   // actual content is ignored (enforce 0 length?)
            case NUMERIC_STRING:
                return new DERNumericString(defIn.toByteArray());
            case OBJECT_IDENTIFIER:
                return ASN1ObjectIdentifier.fromOctetString(defIn.toByteArray());
            case OCTET_STRING:
                return new DEROctetString(defIn.toByteArray());
            case PRINTABLE_STRING:
                return new DERPrintableString(defIn.toByteArray());
            case T61_STRING:
                return new DERT61String(defIn.toByteArray());
            case UNIVERSAL_STRING:
                return new DERUniversalString(defIn.toByteArray());
            case UTC_TIME:
                return new ASN1UTCTime(defIn.toByteArray());
            case UTF8_STRING:
                return new DERUTF8String(defIn.toByteArray());
            case VISIBLE_STRING:
                return new DERVisibleString(defIn.toByteArray());
            default:
                throw new IOException("unknown tag " + tagNo + " encountered");
        }
    }

    protected static ASN1Primitive createPrimitiveDERObject2(
            int tagNo, DefiniteLengthInputStream defIn) throws IOException {
        switch (tagNo) {
            case BIT_STRING:
                return DERBitString.fromInputStream(defIn.getRemaining(), defIn);
            case BMP_STRING:
                return DERBMPString.getInstance(getBMPCharBuffer(defIn));
            case BOOLEAN:
                return ASN1Boolean.getInstance(defIn.toByteArray());
            case ENUMERATED:
                return ASN1Enumerated.getInstance(defIn.toByteArray());
            case GENERALIZED_TIME:
                return ASN1GeneralizedTime.getInstance(defIn.toByteArray());
            case GENERAL_STRING:
                return DERGeneralString.getInstance(defIn.toByteArray());
            case IA5_STRING:
                return DERIA5String.getInstance(defIn.toByteArray());
            case INTEGER:
                return new ASN1Integer(defIn.toByteArray(), false);
            case NULL:
                return DERNull.INSTANCE;   // actual content is ignored (enforce 0 length?)
            case NUMERIC_STRING:
                return DERNumericString.getInstance(defIn.toByteArray());
            case OBJECT_IDENTIFIER:
                return ASN1ObjectIdentifier.getInstance(defIn.toByteArray());
            case OCTET_STRING:
                return new DEROctetString(defIn.toByteArray());
            case PRINTABLE_STRING:
                return DERPrintableString.getInstance(defIn.toByteArray());
            case T61_STRING:
                return new DERT61String(defIn.toByteArray());
            case UNIVERSAL_STRING:
                return new DERUniversalString(defIn.toByteArray());
            case UTC_TIME:
                return ASN1UTCTime.getInstance(defIn.toByteArray());
            case UTF8_STRING:
                return DERUTF8String.getInstance(defIn.toByteArray());
            case VISIBLE_STRING:
                return DERVisibleString.getInstance(defIn.toByteArray());
            default:
                throw new IOException("unknown tag " + tagNo + " encountered");
        }
    }

    private ASN1Primitive readTaggedObject(InputStream in, boolean constructed, int tag) throws IOException {
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
