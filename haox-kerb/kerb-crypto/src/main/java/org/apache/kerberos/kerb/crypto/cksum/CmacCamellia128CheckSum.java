package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.crypto.enc.provider.Camellia128Provider;
import org.apache.kerberos.kerb.crypto.key.CamelliaKeyMaker;
import org.apache.kerberos.kerb.spec.common.CheckSumType;

public class CmacCamellia128CheckSum extends CmacKcCheckSum {

    public CmacCamellia128CheckSum() {
        super(new Camellia128Provider(), 16, 16);

        keyMaker(new CamelliaKeyMaker((Camellia128Provider) encProvider()));
    }

    public int confounderSize() {
        return 16;
    }

    public CheckSumType cksumType() {
        return CheckSumType.CMAC_CAMELLIA128;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 16;  // bytes
    }

    public int keySize() {
        return 16;   // bytes
    }
}
