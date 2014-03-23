package org.haox.kerb.spec.type.kdc.impl;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.common.PaData;
import org.haox.kerb.spec.type.common.impl.AbstractMessage;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.kdc.KdcReqBody;

public abstract class KdcReqImpl extends AbstractMessage implements KdcReq {
    @Override
    public KrbTag[] getTags() {
        return Tag.values();
    }

    public KdcReqImpl(KrbMessageType msgType) throws KrbException {
        super(msgType);
    }

    @Override
    public PaData getPaData() throws KrbException {
        return getFieldAs(Tag.PADATA, PaData.class);
    }

    @Override
    public void setPaData(PaData paData) throws KrbException {
        setField(Tag.PADATA, paData);
    }

    @Override
    public KdcReqBody getReqBody() throws KrbException {
        return getFieldAs(Tag.PADATA, KdcReqBody.class);
    }

    @Override
    public void setReqBody(KdcReqBody reqBody) throws KrbException {
        setField(Tag.REQ_BODY, reqBody);
    }
}
