package org.haox.kerb.crypto.enc;

import org.haox.kerb.spec.common.EncryptionType;

public class Rc4HmacExpEnc extends Rc4HmacEnc {

    public Rc4HmacExpEnc() {
        super(true);
    }

    public EncryptionType eType() {
        return EncryptionType.ARCFOUR_HMAC_EXP;
    }
}
