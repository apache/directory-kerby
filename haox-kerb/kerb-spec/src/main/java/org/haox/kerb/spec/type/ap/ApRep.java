package org.haox.kerb.spec.type.ap;

import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;

/**
 AP-REP          ::= [APPLICATION 15] SEQUENCE {
 pvno            [0] INTEGER (5),
 msg-type        [1] INTEGER (15),
 enc-part        [2] EncryptedData -- EncAPRepPart
 }
 */
public abstract class ApRep extends KrbMessage {
    private EncAPRepPart encPart;
    private EncryptedData encryptedEncPart;

    public ApRep() {
        super(KrbMessageType.AP_REP);
    }

    public EncAPRepPart getEncPart() {
        return encPart;
    }

    public void setEncPart(EncAPRepPart encPart) {
        this.encPart = encPart;
    }

    public EncryptedData getEncryptedEncPart() {
        return encryptedEncPart;
    }

    public void setEncryptedEncPart(EncryptedData encryptedEncPart) {
        this.encryptedEncPart = encryptedEncPart;
    }
}
