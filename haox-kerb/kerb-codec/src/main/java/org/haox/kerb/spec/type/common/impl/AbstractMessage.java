package org.haox.kerb.spec.type.common.impl;

import org.haox.kerb.codec.AbstractSequenceType;
import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;

public abstract class AbstractMessage extends AbstractSequenceType implements KrbMessage {
    private final int pvno = KrbConstant.KERBEROS_V5;

    public AbstractMessage(KrbMessageType msgType) throws KrbException {
        super();
        setPvno(pvno);
        setMsgType(msgType);
    }

    @Override
    public int getPvno() {
        return pvno;
    }

    @Override
    public KrbMessageType getMsgType() throws KrbException {
        KrbInteger value = getFieldAs(1, KrbInteger.class);
        return KrbMessageType.fromValue(value);
    }

    @Override
    public void setMsgType(KrbMessageType msgType) throws KrbException {
        setField(1, msgType.asInteger());
    }

    protected void setPvno(int pvno) throws KrbException {
        setField(0, KrbTypes.makeInteger(pvno));
    }
}
