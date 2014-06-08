package org.haox.asn1;

import org.haox.asn1.type.Asn1UtcTime;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

public class TestAsn1UtcTime {

    @Test
    public void testEncoding() throws Exception {
        /**
         * Cryptography for Developers -> ASN.1 UTCTIME Type
         * the encoding of July 4, 2003 at 11:33 and 28 seconds would be
         “030704113328Z” and be encoded as 0x17 0D 30 33 30 37 30 34 31 31 33 33 32 38 5A.
         */
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        String dateInString = "2003-07-04 11:33:28";
        Date date = sdf.parse(dateInString);
        testEncodingWith(date, "0x17 0D 30 33 30 37 30 34 31 31 33 33 32 38 5A");
    }

    private void testEncodingWith(Date value, String expectedEncoding) {
        byte[] expected = Util.hex2bytes(expectedEncoding);
        Asn1UtcTime aValue = new Asn1UtcTime(value);
        aValue.setEncodingOption(EncodingOption.DER);
        byte[] encodingBytes = aValue.encode();
        Assert.assertArrayEquals(expected, encodingBytes);
    }

    @Test
    public void testDecoding() throws Exception {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String dateInString = "2003-07-04 11:33:28";
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        Date date = sdf.parse(dateInString);
        testDecodingWith(date, "0x17 0D 30 33 30 37 30 34 31 31 33 33 32 38 5A");
    }

    private void testDecodingWith(Date expectedValue, String content) throws IOException {
        Asn1UtcTime decoded = new Asn1UtcTime();
        decoded.setEncodingOption(EncodingOption.DER);
        decoded.decode(Util.hex2bytes(content));
        Assert.assertEquals(expectedValue, decoded.getValue());
    }
}
