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
import org.apache.kerby.asn1.ImplicitField;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 DHRepInfo ::= SEQUENCE {
    dhSignedData            [0] IMPLICIT OCTET STRING,
    serverDHNonce           [1] DHNonce OPTIONAL
    kdf                     [2] KDFAlgorithmId OPTIONAL,
                                -- The KDF picked by the KDC.
 }
 */
public class DHRepInfo extends KrbSequenceType {
    protected enum DHRepInfoField implements EnumType {
        DH_SIGNED_DATA,
        SERVER_DH_NONCE,
        KDF_ID;

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
            new ImplicitField(DHRepInfoField.DH_SIGNED_DATA, Asn1OctetString.class),
            new ExplicitField(DHRepInfoField.SERVER_DH_NONCE, DHNonce.class),
            new ExplicitField(DHRepInfoField.KDF_ID, KDFAlgorithmId.class)
    };

    public DHRepInfo() {
        super(fieldInfos);
    }

    public byte[] getDHSignedData() {
        return getFieldAsOctets(DHRepInfoField.DH_SIGNED_DATA);
    }

    public void setDHSignedData(byte[] dhSignedData) {
        setFieldAsOctets(DHRepInfoField.DH_SIGNED_DATA, dhSignedData);
    }

    public DHNonce getServerDhNonce() {
        return getFieldAs(DHRepInfoField.SERVER_DH_NONCE, DHNonce.class);
    }

    public void setServerDhNonce(DHNonce dhNonce) {
        setFieldAs(DHRepInfoField.SERVER_DH_NONCE, dhNonce);
    }

    public KDFAlgorithmId getKdfId() {
        return getFieldAs(DHRepInfoField.KDF_ID, KDFAlgorithmId.class);
    }

    public void setKdfId(KDFAlgorithmId kdfId) {
        setFieldAs(DHRepInfoField.KDF_ID, kdfId);
    }
}
