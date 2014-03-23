package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.PaData;
import org.haox.kerb.spec.type.common.PaDataEntry;

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
public interface KdcReq extends KrbMessage {
    public static enum Tag implements KrbTag {
        PVNO(1, KrbInteger.class),
        MSG_TYPE(2, KrbInteger.class),
        PADATA(3, PaData.class),
        REQ_BODY(4, KdcReqBody.class);

        private int value;
        private Class<? extends KrbType> type;

        private Tag(int value, Class<? extends KrbType> type) {
            this.value = value;
            this.type = type;
        }

        @Override
        public int getValue() {
            return value;
        }

        @Override
        public int getIndex() {
            return ordinal() - 1;
        }

        @Override
        public Class<? extends KrbType> getType() {
            return type;
        }
    };

    public PaData getPaData() throws KrbException;

    public void setPaData(PaData paData) throws KrbException;

    public KdcReqBody getReqBody() throws KrbException;

    public void setReqBody(KdcReqBody reqBody) throws KrbException;
}
