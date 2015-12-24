/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.kerberos.kerb.type.kdc;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;

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
    protected enum KdcReqField implements EnumType {
        PVNO,
        MSG_TYPE,
        PADATA,
        REQ_BODY;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(KdcReqField.PVNO, 1, Asn1Integer.class),
            new ExplicitField(KdcReqField.MSG_TYPE, 2, Asn1Integer.class),
            new ExplicitField(KdcReqField.PADATA, 3, PaData.class),
            new ExplicitField(KdcReqField.REQ_BODY, 4, KdcReqBody.class)
    };

    public KdcReq(KrbMessageType msgType) {
        super(msgType, fieldInfos);
    }

    public PaData getPaData() {
        return getFieldAs(KdcReqField.PADATA, PaData.class);
    }

    public void setPaData(PaData paData) {
        setFieldAs(KdcReqField.PADATA, paData);
    }

    public void addPaData(PaDataEntry paDataEntry) {
        if (getPaData() == null) {
            setPaData(new PaData());
        }
        getPaData().addElement(paDataEntry);
    }

    public KdcReqBody getReqBody() {
        return getFieldAs(KdcReqField.REQ_BODY, KdcReqBody.class);
    }

    public void setReqBody(KdcReqBody reqBody) {
        setFieldAs(KdcReqField.REQ_BODY, reqBody);
    }
}
