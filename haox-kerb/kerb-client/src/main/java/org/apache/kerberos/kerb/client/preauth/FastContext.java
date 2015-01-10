package org.apache.kerberos.kerb.client.preauth;

import org.apache.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerberos.kerb.spec.fast.FastOptions;
import org.apache.kerberos.kerb.spec.fast.KrbFastArmor;
import org.apache.kerberos.kerb.spec.kdc.KdcReq;

public class FastContext {

    public KdcReq fastOuterRequest;
    public EncryptionKey armorKey;
    public KrbFastArmor fastArmor;
    public FastOptions fastOptions;
    public int nonce;
    public int fastFlags;

}
