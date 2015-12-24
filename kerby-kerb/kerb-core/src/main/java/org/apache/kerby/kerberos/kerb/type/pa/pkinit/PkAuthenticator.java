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
package org.apache.kerby.kerberos.kerb.type.pa.pkinit;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 PKAuthenticator ::= SEQUENCE {
     cusec                   [0] INTEGER (0..999999),
     ctime                   [1] KerberosTime,
     -- cusec and ctime are used as in [RFC4120], for
     -- replay prevention.
     nonce                   [2] INTEGER (0..4294967295),
     -- Chosen randomly; this nonce does not need to
     -- match with the nonce in the KDC-REQ-BODY.
     paChecksum              [3] OCTET STRING OPTIONAL,
     -- MUST be present.
     -- Contains the SHA1 checksum, performed over
     -- KDC-REQ-BODY.
 }
 */
public class PkAuthenticator extends KrbSequenceType {
    protected enum PkAuthenticatorField implements EnumType {
        CUSEC,
        CTIME,
        NONCE,
        PA_CHECKSUM;

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
            new ExplicitField(PkAuthenticatorField.CUSEC, Asn1Integer.class),
            new ExplicitField(PkAuthenticatorField.CTIME, KerberosTime.class),
            new ExplicitField(PkAuthenticatorField.NONCE, Asn1Integer.class),
            new ExplicitField(PkAuthenticatorField.PA_CHECKSUM, Asn1OctetString.class)
    };

    public PkAuthenticator() {
        super(fieldInfos);
    }

    public int getCusec() {
        return getFieldAsInt(PkAuthenticatorField.CUSEC);
    }

    public void setCusec(int cusec) {
        setFieldAsInt(PkAuthenticatorField.CUSEC, cusec);
    }

    public KerberosTime getCtime() {
        return getFieldAsTime(PkAuthenticatorField.CTIME);
    }

    public void setCtime(KerberosTime ctime) {
        setFieldAs(PkAuthenticatorField.CTIME, ctime);
    }

    public int getNonce() {
        return getFieldAsInt(PkAuthenticatorField.NONCE);
    }

    public void setNonce(int nonce) {
        setFieldAsInt(PkAuthenticatorField.NONCE, nonce);
    }

    public byte[] getPaChecksum() {
        return getFieldAsOctets(PkAuthenticatorField.PA_CHECKSUM);
    }

    public void setPaChecksum(byte[] paChecksum) {
        setFieldAsOctets(PkAuthenticatorField.PA_CHECKSUM, paChecksum);
    }
}
