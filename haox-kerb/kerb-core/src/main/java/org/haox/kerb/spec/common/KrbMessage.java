package org.haox.kerb.spec.common;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.haox.kerb.KrbConstant;
import org.haox.kerb.spec.KrbAppSequenceType;

public abstract class KrbMessage extends KrbAppSequenceType {
    protected static int PVNO = 0;
    protected static int MSG_TYPE = 1;

    private final int pvno = KrbConstant.KRB_V5;

    public KrbMessage(KrbMessageType msgType, Asn1FieldInfo[] fieldInfos) {
        super(msgType.getValue(), fieldInfos);
        setPvno(pvno);
        setMsgType(msgType);
    }

    public int getPvno() {
        return pvno;
    }

    protected void setPvno(int pvno) {
        setFieldAsInt(0, pvno);
    }

    public KrbMessageType getMsgType() {
        Integer value = getFieldAsInteger(MSG_TYPE);
        return KrbMessageType.fromValue(value);
    }

    public void setMsgType(KrbMessageType msgType) {
        setFieldAsInt(MSG_TYPE, msgType.getValue());
    }
}
