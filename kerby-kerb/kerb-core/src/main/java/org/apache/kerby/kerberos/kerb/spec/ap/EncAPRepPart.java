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
package org.apache.kerby.kerberos.kerb.spec.ap;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.KrbAppSequenceType;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;

/**
 EncAPRepPart    ::= [APPLICATION 27] SEQUENCE {
 ctime           [0] KerberosTime,
 cusec           [1] Microseconds,
 subkey          [2] EncryptionKey OPTIONAL,
 seq-number      [3] UInt32 OPTIONAL
 }
 */
public class EncAPRepPart extends KrbAppSequenceType {
    public static int TAG = 27;
    private static int CTIME = 0;
    private static int CUSEC = 1;
    private static int SUBKEY = 2;
    private static int SEQ_NUMBER = 3;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(CTIME, 0, KerberosTime.class),
            new Asn1FieldInfo(CUSEC, 1, Asn1Integer.class),
            new Asn1FieldInfo(SUBKEY, 2, EncryptionKey.class),
            new Asn1FieldInfo(SEQ_NUMBER, 3, Asn1Integer.class)
    };

    public EncAPRepPart() {
        super(TAG, fieldInfos);
    }

    public KerberosTime getCtime() {
        return getFieldAsTime(CTIME);
    }

    public void setCtime(KerberosTime ctime) {
        setFieldAs(CTIME, ctime);
    }

    public int getCusec() {
        return getFieldAsInt(CUSEC);
    }

    public void setCusec(int cusec) {
        setFieldAsInt(CUSEC, cusec);
    }

    public EncryptionKey getSubkey() {
        return getFieldAs(SUBKEY, EncryptionKey.class);
    }

    public void setSubkey(EncryptionKey subkey) {
        setFieldAs(SUBKEY, subkey);
    }

    public int getSeqNumber() {
        return getFieldAsInt(SEQ_NUMBER);
    }

    public void setSeqNumber(Integer seqNumber) {
        setFieldAsInt(SEQ_NUMBER, seqNumber);
    }
}
