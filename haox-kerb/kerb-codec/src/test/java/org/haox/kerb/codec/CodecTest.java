package org.haox.kerb.codec;

import junit.framework.Assert;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.MyChecksum;
import org.haox.kerb.spec.type.common.impl.MyChecksumImpl;
import org.junit.Test;

public class CodecTest {

    @Test
    public void testCodec() throws KrbException {
        MyChecksum mcs = new MyChecksumImpl();
        byte[] bytes = KrbCodec.encode(mcs);
        Assert.assertNotNull(bytes);

        MyChecksum restored = (MyChecksum) KrbCodec.decode(bytes, MyChecksum.class);
        Assert.assertNotNull(restored);
    }
}
