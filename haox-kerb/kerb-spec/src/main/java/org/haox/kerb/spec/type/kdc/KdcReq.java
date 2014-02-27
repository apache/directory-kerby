package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.common.PaData;

import java.util.List;

/**
 KDC-REQ         ::= SEQUENCE {
 -- NOTE: first tag is [1], not [0]
 pvno            [1] INTEGER (5) ,
 msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
 padata          [3] SEQUENCE OF PA-DATA OPTIONAL
 -- NOTE: not empty --,
 req-body        [4] KDC-REQ-BODY
 }
 */
public abstract class KdcReq extends KrbMessage {
    private List<PaData> paDataList;
    private KdcReqBody reqBody;

    public KdcReq(KrbMessageType msgType) {
        super(msgType);
    }

    public List<PaData> getPaDataList() {
        return paDataList;
    }

    public void setPaDataList(List<PaData> paDataList) {
        this.paDataList = paDataList;
    }

    public KdcReqBody getReqBody() {
        return reqBody;
    }

    public void setReqBody(KdcReqBody reqBody) {
        this.reqBody = reqBody;
    }
}
