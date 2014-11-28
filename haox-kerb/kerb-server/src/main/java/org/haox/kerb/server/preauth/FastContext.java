package org.haox.kerb.server.preauth;

import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.fast.FastOptions;
import org.haox.kerb.spec.type.fast.KrbFastArmor;
import org.haox.kerb.spec.type.kdc.KdcReq;

public class FastContext {

    public KdcReq fastOuterRequest;
    public EncryptionKey armorKey;
    public KrbFastArmor fastArmor;
    public FastOptions fastOptions;
    public int nonce;
    public int fastFlags;

}
