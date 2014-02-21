package org.haox.kerb.decoding;

import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

public final class DecodingUtil {

    private static final String FORMAT = "%1$02x";

    private DecodingUtil() {}

    public static final String asHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for(byte b : bytes)
            builder.append(String.format(FORMAT, b));

        return builder.toString();
    }

    public static final byte[] asBytes(int integer) {
        byte[] bytes = new byte[]{(byte)integer, (byte)(integer >>> 8), (byte)(integer >>> 16),
                (byte)(integer >>> 24)};

        return bytes;
    }

    public static <T> T as(Class<T> type, Object object) throws DecodingException {

        if(!type.isInstance(object)) {
            Object[] args = new Object[]{type, object.getClass()};
            throw new DecodingException("object.cast.fail", args, null);
        }

        return type.cast(object);
    }

    public static <T extends Object> T as(Class<T> type, Enumeration<?> enumeration)
            throws DecodingException {

        return as(type, enumeration.nextElement());
    }

    public static <T extends DERObject> T as(Class<T> type, ASN1InputStream stream)
            throws DecodingException, IOException {

        return as(type, stream.readObject());
    }

    public static <T extends DERObject> T as(Class<T> type, ASN1TaggedObject tagged)
            throws DecodingException {

        return as(type, tagged.getObject());
    }

    public static <T extends DERObject> T as(Class<T> type, DERSequence sequence, int index)
            throws DecodingException {

        return as(type, sequence.getObjectAt(index));
    }

}
