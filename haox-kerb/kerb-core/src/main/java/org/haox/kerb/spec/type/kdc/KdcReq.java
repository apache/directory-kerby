package org.haox.kerb.spec.type.kdc;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.AbstractKrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.common.PaData;

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
public class KdcReq extends AbstractKrbMessage {
    private static int PADATA = 2;
    private static int REQ_BODY = 3;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PVNO, 1, Asn1Integer.class),
            new Asn1FieldInfo(MSG_TYPE, 2, Asn1Integer.class),
            new Asn1FieldInfo(PADATA, 3, PaData.class),
            new Asn1FieldInfo(REQ_BODY, 4, KdcReqBody.class)
    };

    public KdcReq(KrbMessageType msgType) throws KrbException {
        super(msgType, fieldInfos);
    }

    public PaData getPaData() throws KrbException {
        return getFieldAs(PADATA, PaData.class);
    }

    public void setPaData(PaData paData) throws KrbException {
        setFieldAs(PADATA, paData);
    }

    public KdcReqBody getReqBody() throws KrbException {
        return getFieldAs(PADATA, KdcReqBody.class);
    }

    public void setReqBody(KdcReqBody reqBody) throws KrbException {
        setFieldAs(REQ_BODY, reqBody);
    }
}
