package org.haox.kerb.spec.kdc;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.common.KrbMessage;
import org.haox.kerb.spec.common.KrbMessageType;
import org.haox.kerb.spec.pa.PaData;
import org.haox.kerb.spec.pa.PaDataEntry;

/**
 KDC-REQ         ::= SEQUENCE {
 -- NOTE: first tag is [1], not [0]
 pvno            [1] INTEGER (5) ,
 msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
 padata          [3] SEQUENCE OF PA-DATA OPTIONAL
 -- NOTE: not empty --,
 req-encodeBody        [4] KDC-REQ-BODY
 }
 */
public class KdcReq extends KrbMessage {
    private static int PADATA = 2;
    private static int REQ_BODY = 3;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PVNO, 1, Asn1Integer.class),
            new Asn1FieldInfo(MSG_TYPE, 2, Asn1Integer.class),
            new Asn1FieldInfo(PADATA, 3, PaData.class),
            new Asn1FieldInfo(REQ_BODY, 4, KdcReqBody.class)
    };

    public KdcReq(KrbMessageType msgType) {
        super(msgType, fieldInfos);
    }

    public PaData getPaData() {
        return getFieldAs(PADATA, PaData.class);
    }

    public void setPaData(PaData paData) {
        setFieldAs(PADATA, paData);
    }

    public void addPaData(PaDataEntry paDataEntry) {
        if (getPaData() == null) {
            setPaData(new PaData());
        }
        getPaData().addElement(paDataEntry);
    }

    public KdcReqBody getReqBody() {
        return getFieldAs(REQ_BODY, KdcReqBody.class);
    }

    public void setReqBody(KdcReqBody reqBody) {
        setFieldAs(REQ_BODY, reqBody);
    }
}
