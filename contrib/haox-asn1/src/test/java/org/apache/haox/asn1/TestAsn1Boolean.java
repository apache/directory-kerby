package org.apache.haox.asn1;

import org.apache.haox.asn1.type.Asn1Boolean;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class TestAsn1Boolean {

    @Test
    public void testEncoding() {
        testEncodingWith(true, "0x01 01 FF");
        testEncodingWith(false, "0x01 01 00");
    }

    private void testEncodingWith(Boolean value, String expectedEncoding) {
        byte[] expected = Util.hex2bytes(expectedEncoding);
        Asn1Boolean aValue = new Asn1Boolean(value);
        aValue.setEncodingOption(EncodingOption.DER);
        byte[] encodingBytes = aValue.encode();
        Assert.assertArrayEquals(expected, encodingBytes);
    }

    @Test
    public void testDecoding() throws IOException {
        testDecodingWith(true, "0x01 01 FF");
        testDecodingWith(false, "0x01 01 00");
    }

    private void testDecodingWith(Boolean expectedValue, String content) throws IOException {
        Asn1Boolean decoded = new Asn1Boolean();
        decoded.setEncodingOption(EncodingOption.DER);
        decoded.decode(Util.hex2bytes(content));
        Assert.assertEquals(expectedValue, decoded.getValue());
    }
}
