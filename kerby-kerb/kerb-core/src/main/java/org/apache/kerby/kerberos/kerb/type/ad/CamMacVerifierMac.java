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
package org.apache.kerby.kerberos.kerb.type.ad;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;
import org.apache.kerby.kerberos.kerb.type.base.CheckSum;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;

/**
 * <pre>
 * Verifier-MAC ::= SEQUENCE { 
 *      identifier [0]  PrincipalName OPTIONAL, 
 *      kvno [1]        UInt32 OPTIONAL, 
 *      enctype [2]     Int32 OPTIONAL, 
 *      mac [3]         Checksum
 * }
 * </pre>
 * 
 * Contributed to the Apache Kerby Project by: Prodentity - Corrales, NM
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache DirectoryProject</a>
 */
public class CamMacVerifierMac extends KrbSequenceType {

    protected enum CamMacField implements EnumType {
        CAMMAC_identifier, CAMMAC_kvno, CAMMAC_enctype, CAMMAC_mac;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    /** The CamMac's fields */
    private static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(CamMacField.CAMMAC_identifier, PrincipalName.class),
            new ExplicitField(CamMacField.CAMMAC_kvno, Asn1Integer.class),
            new ExplicitField(CamMacField.CAMMAC_enctype, Asn1Integer.class),
            new ExplicitField(CamMacField.CAMMAC_mac, CheckSum.class)};

    public CamMacVerifierMac() {
        super(fieldInfos);
    }

    public CamMacVerifierMac(PrincipalName identifier) {
        super(fieldInfos);
        setFieldAs(CamMacField.CAMMAC_identifier, identifier);
    }

    public PrincipalName getIdentifier() {
        return getFieldAs(CamMacField.CAMMAC_identifier, PrincipalName.class);
    }

    public void setIdentifier(PrincipalName identifier) {
        setFieldAs(CamMacField.CAMMAC_identifier, identifier);
    }

    public int getKvno() {
        return getFieldAs(CamMacField.CAMMAC_kvno, Asn1Integer.class).getValue().intValue();
    }

    public void setKvno(int kvno) {
        setFieldAs(CamMacField.CAMMAC_kvno, new Asn1Integer(kvno));
    }

    public int getEnctype() {
        return getFieldAs(CamMacField.CAMMAC_enctype, Asn1Integer.class).getValue().intValue();
    }

    public void setEnctype(int encType) {
        setFieldAs(CamMacField.CAMMAC_enctype, new Asn1Integer(encType));
    }

    public CheckSum getMac() {
        return getFieldAs(CamMacField.CAMMAC_mac, CheckSum.class);
    }

    public void setMac(CheckSum mac) {
        setFieldAs(CamMacField.CAMMAC_mac, mac);
    }
}
