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
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;

/**
 KrbFastResponse ::= SEQUENCE {
     padata         [0] SEQUENCE OF PA-DATA,
     -- padata typed holes.
     strengthen-key [1] EncryptionKey OPTIONAL,
     -- This, if present, strengthens the reply key for AS and
     -- TGS. MUST be present for TGS.
     -- MUST be absent in KRB-ERROR.
     finished       [2] KrbFastFinished OPTIONAL,
     -- Present in AS or TGS reply; absent otherwise.
     nonce          [3] UInt32,
     -- Nonce from the client request.
 }
 */
public class KrbFastResponse extends KrbSequenceType {
    protected enum KrbFastResponseField implements EnumType {
        PADATA,
        STRENGTHEN_KEY,
        FINISHED,
        NONCE;

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
            new ExplicitField(KrbFastResponseField.PADATA, PaData.class),
            new ExplicitField(KrbFastResponseField.STRENGTHEN_KEY, EncryptionKey.class),
            new ExplicitField(KrbFastResponseField.FINISHED, KrbFastFinished.class),
            new ExplicitField(KrbFastResponseField.NONCE, Asn1Integer.class)
    };

    public KrbFastResponse() {
        super(fieldInfos);
    }

    public PaData getPaData() {
        return getFieldAs(KrbFastResponseField.PADATA, PaData.class);
    }

    public void setPaData(PaData paData) {
        setFieldAs(KrbFastResponseField.PADATA, paData);
    }

    public EncryptionKey getStrengthenKey() {
        return getFieldAs(KrbFastResponseField.STRENGTHEN_KEY, EncryptionKey.class);
    }

    public void setStrengthenKey(EncryptionKey strengthenKey) {
        setFieldAs(KrbFastResponseField.STRENGTHEN_KEY, strengthenKey);
    }

    public KrbFastFinished getFastFinished() {
        return getFieldAs(KrbFastResponseField.FINISHED, KrbFastFinished.class);
    }

    public void setFastFinished(KrbFastFinished fastFinished) {
        setFieldAs(KrbFastResponseField.FINISHED, fastFinished);
    }

    public int getNonce() {
        return getFieldAsInt(KrbFastResponseField.NONCE);
    }

    public void setNonce(int nonce) {
        setFieldAsInt(KrbFastResponseField.NONCE, nonce);
    }
}
