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

import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1OctetString;

/**
 PA-PK-AS-REP ::= CHOICE {
    dhInfo                  [0] DHRepInfo,
    encKeyPack              [1] IMPLICIT OCTET STRING,
 }
 */
public class PaPkAsRep extends Asn1Choice {
    private static int DH_INFO = 0;
    private static int ENCKEY_PACK = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(DH_INFO, DHRepInfo.class),
            new Asn1FieldInfo(ENCKEY_PACK, Asn1OctetString.class, true)
    };

    public PaPkAsRep() {
        super(fieldInfos);
    }

    public DHRepInfo getDHRepInfo() {
        return getFieldAs(DH_INFO, DHRepInfo.class);
    }

    public void setDHRepInfo(DHRepInfo dhRepInfo) {
        setFieldAs(DH_INFO, dhRepInfo);
    }

    public byte[] getEncKeyPack() {
        return getFieldAsOctets(ENCKEY_PACK);
    }

    public void setEncKeyPack(byte[] encKeyPack) {
        setFieldAsOctets(ENCKEY_PACK, encKeyPack);
    }
}
