package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.enc.provider.Camellia128Provider;
import org.haox.kerb.crypto.key.CamelliaKeyMaker;
import org.haox.kerb.spec.common.CheckSumType;
import org.haox.kerb.spec.common.EncryptionType;

public class Camellia128CtsCmacEnc extends KeKiCmacEnc {

    public Camellia128CtsCmacEnc() {
        super(new Camellia128Provider());
        keyMaker(new CamelliaKeyMaker((Camellia128Provider) encProvider()));
    }

    public EncryptionType eType() {
        return EncryptionType.CAMELLIA128_CTS_CMAC;
    }

    public CheckSumType checksumType() {
        return CheckSumType.CMAC_CAMELLIA128;
    }
}
