package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.SequenceType;

public interface KrbMessage extends SequenceType {

    public int getPvno();

    public KrbMessageType getMsgType() throws KrbException;

    public void setMsgType(KrbMessageType msgType) throws KrbException;
}
