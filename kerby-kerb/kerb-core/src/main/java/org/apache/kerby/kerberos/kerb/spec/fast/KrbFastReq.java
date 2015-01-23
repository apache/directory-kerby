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
package org.apache.kerby.kerberos.kerb.spec.fast;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptedData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;

/**
 KrbFastReq ::= SEQUENCE {
     fast-options [0] FastOptions,
     -- Additional options.
     padata       [1] SEQUENCE OF PA-DATA,
     -- padata typed holes.
     req-body     [2] KDC-REQ-BODY,
     -- Contains the KDC request body as defined in Section
     -- 5.4.1 of [RFC4120].
     -- This req-body field is preferred over the outer field
     -- in the KDC request.
 }
 */
public class KrbFastReq extends KrbSequenceType {
    private static int FAST_OPTIONS = 0;
    private static int PADATA = 1;
    private static int REQ_BODY = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(FAST_OPTIONS, KrbFastArmor.class),
            new Asn1FieldInfo(PADATA, PaData.class),
            new Asn1FieldInfo(REQ_BODY, EncryptedData.class),
    };

    public KrbFastReq() {
        super(fieldInfos);
    }

    public KrbFastArmor getArmor() {
        return getFieldAs(FAST_OPTIONS, KrbFastArmor.class);
    }

    public void setArmor(KrbFastArmor armor) {
        setFieldAs(FAST_OPTIONS, armor);
    }

    public PaData getPaData() {
        return getFieldAs(PADATA, PaData.class);
    }

    public void setPaData(PaData paData) {
        setFieldAs(PADATA, paData);
    }

    public EncryptedData getEncFastReq() {
        return getFieldAs(REQ_BODY, EncryptedData.class);
    }

    public void setEncFastReq(EncryptedData encFastReq) {
        setFieldAs(REQ_BODY, encFastReq);
    }
}
