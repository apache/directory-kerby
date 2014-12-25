package org.haox.kerb.client.preauth;

import org.haox.kerb.spec.common.EncryptionKey;
import org.haox.kerb.spec.fast.FastOptions;
import org.haox.kerb.spec.fast.KrbFastArmor;
import org.haox.kerb.spec.kdc.KdcReq;

public class FastContext {

    public KdcReq fastOuterRequest;
    public EncryptionKey armorKey;
    public KrbFastArmor fastArmor;
    public FastOptions fastOptions;
    public int nonce;
    public int fastFlags;

}
