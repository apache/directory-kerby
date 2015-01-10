package org.apache.haox.asn1;

import org.junit.Test;

import java.io.IOException;

public class TestAsn1Input {

    @Test
    public void testDecoding() throws IOException {
        //PersonnelRecord expected = TestData.createSamplePersonnel();
        byte[] data = TestData.createSammplePersonnelEncodingData();
        //Asn1InputBuffer ib = new Asn1InputBuffer(data);
        Asn1Dump.dump(data);
    }
}
