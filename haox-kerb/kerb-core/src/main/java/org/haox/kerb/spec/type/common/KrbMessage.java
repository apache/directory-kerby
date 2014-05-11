package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.type.KrbAppSequenceType;

public abstract class KrbMessage extends KrbAppSequenceType {
    protected static int PVNO = 0;
    protected static int MSG_TYPE = 1;

    private final int pvno = KrbConstant.KERBEROS_V5;

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
