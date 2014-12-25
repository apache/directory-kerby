package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.enc.provider.Camellia256Provider;
import org.haox.kerb.crypto.key.CamelliaKeyMaker;
import org.haox.kerb.spec.common.CheckSumType;
import org.haox.kerb.spec.common.EncryptionType;

public class Camellia256CtsCmacEnc extends KeKiCmacEnc {

    public Camellia256CtsCmacEnc() {
        super(new Camellia256Provider());
        keyMaker(new CamelliaKeyMaker((Camellia256Provider) encProvider()));
    }

    public EncryptionType eType() {
        return EncryptionType.CAMELLIA256_CTS_CMAC;
    }

    public CheckSumType checksumType() {
        return CheckSumType.CMAC_CAMELLIA256;
    }
}
