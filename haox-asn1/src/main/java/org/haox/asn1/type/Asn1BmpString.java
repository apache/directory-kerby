package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.UniversalTag;
import org.haox.asn1.LimitedByteBuffer;

import java.io.IOException;

public class Asn1BmpString extends AbstractAsn1Simple<String>
{
    public Asn1BmpString() {
        super(null);
    }

    public Asn1BmpString(String value) {
        super(UniversalTag.BMP_STRING, value);
    }

    @Override
    protected int encodingBodyLength(EncodingOption encodingOption) {
        return getValue().length() * 2;
    }

    protected void toBytes(EncodingOption encodingOption) {
        String strValue = getValue();
        int len = strValue.length();
        byte[] bytes = new byte[len * 2];
        char c;
        for (int i = 0; i != len; i++) {
            c = strValue.charAt(i);
            bytes[2 * i] = (byte)(c >> 8);
            bytes[2 * i + 1] = (byte)c;
        }
        setBytes(bytes);
    }

    protected void toValue() throws IOException {
        byte[] bytes = getBytes();
        char[]  chars = new char[bytes.length / 2];
        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char)((bytes[2 * i] << 8) | (bytes[2 * i + 1] & 0xff));
        }
        setValue(new String(chars));
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        if (content.hasLeft() % 2 != 0) {
            throw new IOException("Bad stream, BMP string expecting multiple of 2 bytes");
        }
        super.decodeBody(content);
    }
}
