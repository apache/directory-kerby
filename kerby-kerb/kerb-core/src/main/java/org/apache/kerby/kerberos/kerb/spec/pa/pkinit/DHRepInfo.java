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
package org.apache.kerby.kerberos.kerb.spec.pa.pkinit;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;

/**
 DHRepInfo ::= SEQUENCE {
    dhSignedData            [0] IMPLICIT OCTET STRING,
    serverDHNonce           [1] DHNonce OPTIONAL
 }
 */
public class DHRepInfo extends KrbSequenceType {
    private static int DH_SIGNED_DATA = 0;
    private static int SERVER_DH_NONCE = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(DH_SIGNED_DATA, Asn1OctetString.class, true),
            new Asn1FieldInfo(SERVER_DH_NONCE, DHNonce.class)
    };

    public DHRepInfo() {
        super(fieldInfos);
    }

    public byte[] getDHSignedData() {
        return getFieldAsOctets(DH_SIGNED_DATA);
    }

    public void setDHSignedData(byte[] dhSignedData) {
        setFieldAsOctets(DH_SIGNED_DATA, dhSignedData);
    }

    public DHNonce getServerDhNonce() {
        return getFieldAs(SERVER_DH_NONCE, DHNonce.class);
    }

    public void setServerDhNonce(DHNonce dhNonce) {
        setFieldAs(SERVER_DH_NONCE, dhNonce);
    }
}
