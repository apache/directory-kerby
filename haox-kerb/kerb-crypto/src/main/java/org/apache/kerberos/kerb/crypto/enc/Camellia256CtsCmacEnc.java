package org.apache.kerberos.kerb.crypto.enc;

import org.apache.kerberos.kerb.crypto.enc.provider.Camellia256Provider;
import org.apache.kerberos.kerb.crypto.key.CamelliaKeyMaker;
import org.apache.kerberos.kerb.spec.common.CheckSumType;
import org.apache.kerberos.kerb.spec.common.EncryptionType;

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
