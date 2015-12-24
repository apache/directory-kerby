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
package org.apache.kerby.kerberos.kerb.type.ap;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbAppSequenceType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;

/**
 EncAPRepPart    ::= [APPLICATION 27] SEQUENCE {
 ctime           [0] KerberosTime,
 cusec           [1] Microseconds,
 subkey          [2] EncryptionKey OPTIONAL,
 seq-number      [3] UInt32 OPTIONAL
 }
 */
public class EncAPRepPart extends KrbAppSequenceType {
    public static final int TAG = 27;

    protected enum EncAPRepPartField implements EnumType {
        CTIME,
        CUSEC,
        SUBKEY,
        SEQ_NUMBER;

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
            new ExplicitField(EncAPRepPartField.CTIME, KerberosTime.class),
            new ExplicitField(EncAPRepPartField.CUSEC, Asn1Integer.class),
            new ExplicitField(EncAPRepPartField.SUBKEY, EncryptionKey.class),
            new ExplicitField(EncAPRepPartField.SEQ_NUMBER, Asn1Integer.class)
    };

    public EncAPRepPart() {
        super(TAG, fieldInfos);
    }

    public KerberosTime getCtime() {
        return getFieldAsTime(EncAPRepPartField.CTIME);
    }

    public void setCtime(KerberosTime ctime) {
        setFieldAs(EncAPRepPartField.CTIME, ctime);
    }

    public int getCusec() {
        return getFieldAsInt(EncAPRepPartField.CUSEC);
    }

    public void setCusec(int cusec) {
        setFieldAsInt(EncAPRepPartField.CUSEC, cusec);
    }

    public EncryptionKey getSubkey() {
        return getFieldAs(EncAPRepPartField.SUBKEY, EncryptionKey.class);
    }

    public void setSubkey(EncryptionKey subkey) {
        setFieldAs(EncAPRepPartField.SUBKEY, subkey);
    }

    public int getSeqNumber() {
        return getFieldAsInt(EncAPRepPartField.SEQ_NUMBER);
    }

    public void setSeqNumber(Integer seqNumber) {
        setFieldAsInt(EncAPRepPartField.SEQ_NUMBER, seqNumber);
    }
}
