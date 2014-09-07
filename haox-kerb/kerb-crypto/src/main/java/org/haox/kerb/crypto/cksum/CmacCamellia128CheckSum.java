package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.enc.provider.Aes128Provider;
import org.haox.kerb.crypto.enc.provider.Camellia128Provider;
import org.haox.kerb.crypto.key.AesKeyMaker;
import org.haox.kerb.crypto.key.CamelliaKeyMaker;
import org.haox.kerb.spec.type.common.CheckSumType;

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
