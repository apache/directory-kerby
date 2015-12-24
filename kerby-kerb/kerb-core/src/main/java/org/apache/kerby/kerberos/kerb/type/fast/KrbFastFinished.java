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
package org.apache.kerby.kerberos.kerb.type.fast;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;
import org.apache.kerby.kerberos.kerb.type.base.CheckSum;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;

/**
 KrbFastFinished ::= SEQUENCE {
     timestamp       [0] KerberosTime,
     usec            [1] Microseconds,
     -- timestamp and usec represent the time on the KDC when
     -- the reply was generated.
     crealm          [2] Realm,
     cname           [3] PrincipalName,
     -- Contains the client realm and the client name.
     ticket-checksum [4] Checksum,
     -- checksum of the ticket in the KDC-REP using the armor
     -- and the key usage is KEY_USAGE_FAST_FINISH.
     -- The checksum type is the required checksum type
     -- of the armor key.
 }
 */
public class KrbFastFinished extends KrbSequenceType {
    protected enum KrbFastFinishedField implements EnumType {
        FAST_OPTIONS,
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
            new ExplicitField(KrbFastFinishedField.FAST_OPTIONS, KrbFastArmor.class),
            new ExplicitField(KrbFastFinishedField.PADATA, PaData.class),
            new ExplicitField(KrbFastFinishedField.REQ_BODY, EncryptedData.class),
    };

    public KrbFastFinished() {
        super(fieldInfos);
    }

    public KrbFastArmor getArmor() {
        return getFieldAs(KrbFastFinishedField.FAST_OPTIONS, KrbFastArmor.class);
    }

    public void setArmor(KrbFastArmor armor) {
        setFieldAs(KrbFastFinishedField.FAST_OPTIONS, armor);
    }

    public CheckSum getReqChecksum() {
        return getFieldAs(KrbFastFinishedField.PADATA, CheckSum.class);
    }

    public void setReqChecksum(CheckSum checkSum) {
        setFieldAs(KrbFastFinishedField.PADATA, checkSum);
    }

    public EncryptedData getEncFastReq() {
        return getFieldAs(KrbFastFinishedField.REQ_BODY, EncryptedData.class);
    }

    public void setEncFastReq(EncryptedData encFastReq) {
        setFieldAs(KrbFastFinishedField.REQ_BODY, encFastReq);
    }
}
