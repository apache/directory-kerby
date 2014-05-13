package org.haox.kerb.codec;

import junit.framework.Assert;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.Checksum;
import org.haox.kerb.spec.type.common.ChecksumType;
import org.junit.Test;

import java.util.Arrays;

public class CodecTest {

    @Test
    public void testCodec() throws KrbException {
        Checksum mcs = new Checksum();
        mcs.setCksumtype(ChecksumType.CRC32);
        mcs.setChecksum(new byte[] {0x10});
        byte[] bytes = KrbCodec.encode(mcs);
        Assert.assertNotNull(bytes);

        Checksum restored = KrbCodec.decode(bytes, Checksum.class);
        Assert.assertNotNull(restored);
        Assert.assertEquals(mcs.getCksumtype(), restored.getCksumtype());
        Assert.assertTrue(Arrays.equals(mcs.getChecksum(), restored.getChecksum()));
    }
}
