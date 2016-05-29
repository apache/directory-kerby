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

import java.io.IOException;

import org.apache.kerby.asn1.Asn1Dumper;
import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 * <pre>
 * AD-CAMMAC                   ::= SEQUENCE {
 *          elements              [0] AuthorizationData,
 *          kdc-verifier          [1] Verifier-MAC OPTIONAL,
 *          svc-verifier          [2] Verifier-MAC OPTIONAL,
 *          other-verifiers       [3] SEQUENCE (SIZE (1..MAX))
 *                                    OF Verifier OPTIONAL
 *    }
 * </pre>
 *
 * Contributed to the Apache Kerby Project by: Prodentity - Corrales, NM
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache DirectoryProject</a>
 */
public class ADCamMac extends AuthorizationDataEntry {

    private CamMac myCamMac;

    private static class CamMac extends KrbSequenceType {

        protected enum CamMacField implements EnumType {
            CAMMAC_elements, CAMMAC_kdc_verifier, CAMMAC_svc_verifier, CAMMAC_other_verifiers;

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
                new ExplicitField(CamMacField.CAMMAC_elements, AuthorizationData.class),
                new ExplicitField(CamMacField.CAMMAC_kdc_verifier, CamMacVerifierMac.class),
                new ExplicitField(CamMacField.CAMMAC_svc_verifier, CamMacVerifierMac.class),
                new ExplicitField(CamMacField.CAMMAC_other_verifiers, CamMacOtherVerifiers.class)};

        CamMac() {
            super(fieldInfos);
        }

        CamMac(byte[] authzFields) {
            super(fieldInfos);
            super.setFieldAsOctets(AuthorizationDataEntryField.AD_DATA, authzFields);
        }

        CamMac(AuthorizationData authzData) {
            super(fieldInfos);
            setFieldAs(CamMacField.CAMMAC_elements, authzData);
        }

        public AuthorizationData getAuthorizationData() {
            return getFieldAs(CamMacField.CAMMAC_elements, AuthorizationData.class);
        }

        public void setAuthorizationData(AuthorizationData authzData) {
            setFieldAs(CamMacField.CAMMAC_elements, authzData);
            resetBodyLength();
        }

        public CamMacVerifierMac getKdcVerifier() {
            return getFieldAs(CamMacField.CAMMAC_kdc_verifier, CamMacVerifierMac.class);
        }

        public void setKdcVerifier(CamMacVerifierMac kdcVerifier) {
            setFieldAs(CamMacField.CAMMAC_kdc_verifier, kdcVerifier);
            resetBodyLength();
        }

        public CamMacVerifierMac getSvcVerifier() {
            return getFieldAs(CamMacField.CAMMAC_svc_verifier, CamMacVerifierMac.class);
        }

        public void setSvcVerifier(CamMacVerifierMac svcVerifier) {
            setFieldAs(CamMacField.CAMMAC_svc_verifier, svcVerifier);
            resetBodyLength();
        }

        public CamMacOtherVerifiers getOtherVerifiers() {
            return getFieldAs(CamMacField.CAMMAC_other_verifiers, CamMacOtherVerifiers.class);
        }

        public void setOtherVerifiers(CamMacOtherVerifiers svcVerifier) {
            setFieldAs(CamMacField.CAMMAC_other_verifiers, svcVerifier);
            resetBodyLength();
        }
    }

    public ADCamMac() {
        super(AuthorizationType.AD_CAMMAC);
        myCamMac = new CamMac();
        myCamMac.outerEncodeable = this;
    }

    public ADCamMac(byte[] encoded) throws IOException {
        this();
        myCamMac.decode(encoded);
    }

    public AuthorizationData getAuthorizationData() {
        return myCamMac.getAuthorizationData();
    }

    public void setAuthorizationData(AuthorizationData authzData) {
        myCamMac.setAuthorizationData(authzData);
    }

    public CamMacVerifierMac getKdcVerifier() {
        return myCamMac.getKdcVerifier();
    }

    public void setKdcVerifier(CamMacVerifierMac kdcVerifier) {
        myCamMac.setKdcVerifier(kdcVerifier);
    }

    public CamMacVerifierMac getSvcVerifier() {
        return myCamMac.getSvcVerifier();
    }

    public void setSvcVerifier(CamMacVerifierMac svcVerifier) {
        myCamMac.setSvcVerifier(svcVerifier);
    }

    public CamMacOtherVerifiers getOtherVerifiers() {
        return myCamMac.getOtherVerifiers();
    }

    public void setOtherVerifiers(CamMacOtherVerifiers otherVerifiers) {
        myCamMac.setOtherVerifiers(otherVerifiers);
    }

    @Override
    protected int encodingBodyLength() throws IOException {
        if (bodyLength == -1) {
            setAuthzData(myCamMac.encode());
            bodyLength = super.encodingBodyLength();
        }
        return bodyLength;
    };

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        try {
            setAuthzData(myCamMac.encode());
        } catch (IOException e) {
            e.printStackTrace();
        }
        super.dumpWith(dumper, indents);
        dumper.newLine();
        myCamMac.dumpWith(dumper, indents + 8);
    }

}
