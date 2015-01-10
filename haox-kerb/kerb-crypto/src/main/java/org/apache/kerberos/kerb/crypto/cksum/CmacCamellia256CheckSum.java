package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.crypto.enc.provider.Camellia256Provider;
import org.apache.kerberos.kerb.crypto.key.CamelliaKeyMaker;
import org.apache.kerberos.kerb.spec.common.CheckSumType;

public class CmacCamellia256CheckSum extends CmacKcCheckSum {

    public CmacCamellia256CheckSum() {
        super(new Camellia256Provider(), 16, 16);

        keyMaker(new CamelliaKeyMaker((Camellia256Provider) encProvider()));
    }

    public int confounderSize() {
        return 16;
    }

    public CheckSumType cksumType() {
        return CheckSumType.CMAC_CAMELLIA256;
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
