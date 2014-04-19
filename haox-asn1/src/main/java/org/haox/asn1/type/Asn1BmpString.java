package org.haox.asn1.type;

import java.io.IOException;

public class Asn1BmpString extends AbstractAsn1Primitive<String>
{
    public Asn1BmpString() {
        super(null);
    }

    public Asn1BmpString(String value) {
        super(value, BerTag.BMP_STRING);
    }

    @Override
    protected byte[] body() {
        String strValue = getValue();
        int len = strValue.length();
        byte[] bytes = new byte[len * 2];
        char c;
        for (int i = 0; i != len; i++) {
            c = strValue.charAt(i);
            bytes[2 * i] = (byte)(c >> 8);
            bytes[2 * i + 1] = (byte)c;
        }
        return bytes;
    }

    @Override
    protected int bodyLength() {
        return getValue().length() * 2;
    }

    @Override
    protected void decodeValue(LimitedByteBuffer content) throws IOException {
        if (content.hasLeft() % 2 != 0) {
            throw new IOException("Bad stream, BMP string expecting multiple of 2 bytes");
        }

        byte[] bytes = content.readAllBytes();
        char[]  chars = new char[bytes.length / 2];
        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char)((bytes[2 * i] << 8) | (bytes[2 * i + 1] & 0xff));
        }
        setValue(new String(chars));
    }
}
