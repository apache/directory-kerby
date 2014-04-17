package org.haox.kerb.spec.type.ap;

import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.KrbMessage;

/**
 AP-REP          ::= [APPLICATION 15] SEQUENCE {
 pvno            [0] INTEGER (5),
 msg-type        [1] INTEGER (15),
 enc-part        [2] EncryptedData -- EncAPRepPart
 }
 */
public interface ApRep extends KrbMessage {
    public EncAPRepPart getEncPart();

    public void setEncPart(EncAPRepPart encPart);

    public EncryptedData getEncryptedEncPart();

    public void setEncryptedEncPart(EncryptedData encryptedEncPart);
}
