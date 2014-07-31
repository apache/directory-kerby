package org.haox.kerb.codec;

import junit.framework.Assert;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSum;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.junit.Test;

import java.util.Arrays;

public class CodecTest {

    @Test
    public void testCodec() throws KrbException {
        CheckSum mcs = new CheckSum();
        mcs.setCksumtype(CheckSumType.CRC32);
        mcs.setChecksum(new byte[] {0x10});
        byte[] bytes = KrbCodec.encode(mcs);
        Assert.assertNotNull(bytes);

        CheckSum restored = KrbCodec.decode(bytes, CheckSum.class);
        Assert.assertNotNull(restored);
        Assert.assertEquals(mcs.getCksumtype(), restored.getCksumtype());
        Assert.assertTrue(Arrays.equals(mcs.getChecksum(), restored.getChecksum()));
    }
}
