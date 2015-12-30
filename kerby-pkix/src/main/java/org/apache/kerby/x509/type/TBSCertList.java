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
package org.apache.kerby.x509.type;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.x500.type.Name;

/**
 * Ref. RFC-2459
 * <pre>
 * TBSCertList  ::=  SEQUENCE  {
 *      version                 Version OPTIONAL,
 *                                   -- if present, shall be v2
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      thisUpdate              Time,
 *      nextUpdate              Time OPTIONAL,
 *      revokedCertificates     SEQUENCE OF SEQUENCE  {
 *           userCertificate         CertificateSerialNumber,
 *           revocationDate          Time,
 *           crlEntryExtensions      Extensions OPTIONAL
 *                                         -- if present, shall be v2
 *                                }  OPTIONAL,
 *      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                         -- if present, shall be v2
 *                                }
 * </pre>
 */
public class TBSCertList extends Asn1SequenceType {
    protected enum TBSCertListField implements EnumType {
        VERSION,
        SIGNATURE,
        ISSUER,
        THIS_UPDATA,
        NEXT_UPDATE,
        REVOKED_CERTIFICATES,
        CRL_EXTENSIONS;

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
        new Asn1FieldInfo(TBSCertListField.VERSION, Asn1Integer.class),
        new Asn1FieldInfo(TBSCertListField.SIGNATURE, AlgorithmIdentifier.class),
        new Asn1FieldInfo(TBSCertListField.ISSUER, Name.class),
        new Asn1FieldInfo(TBSCertListField.THIS_UPDATA, Time.class),
        new Asn1FieldInfo(TBSCertListField.NEXT_UPDATE, Time.class),
        new Asn1FieldInfo(TBSCertListField.REVOKED_CERTIFICATES, RevokedCertificates.class),
        new ExplicitField(TBSCertListField.CRL_EXTENSIONS, 0, Extensions.class)
    };

    public TBSCertList() {
        super(fieldInfos);
    }

    public Asn1Integer getVersion() {
        return getFieldAs(TBSCertListField.VERSION, Asn1Integer.class);
    }

    public void setVersion(Asn1Integer version) {
        setFieldAs(TBSCertListField.VERSION, version);
    }

    public AlgorithmIdentifier getSignature() {
        return getFieldAs(TBSCertListField.SIGNATURE, AlgorithmIdentifier.class);
    }

    public void setSignature(AlgorithmIdentifier signature) {
        setFieldAs(TBSCertListField.SIGNATURE, signature);
    }

    public Name getIssuer() {
        return getFieldAs(TBSCertListField.ISSUER, Name.class);
    }

    public void setIssuer(Name issuer) {
        setFieldAs(TBSCertListField.ISSUER, issuer);
    }

    public Time getThisUpdate() {
        return getFieldAs(TBSCertListField.THIS_UPDATA, Time.class);
    }

    public void setThisUpdata(Time thisUpdata) {
        setFieldAs(TBSCertListField.THIS_UPDATA, thisUpdata);
    }

    public Time getNextUpdate() {
        return getFieldAs(TBSCertListField.NEXT_UPDATE, Time.class);
    }

    public void setNextUpdate(Time nextUpdate) {
        setFieldAs(TBSCertListField.NEXT_UPDATE, nextUpdate);
    }

    public RevokedCertificates getRevokedCertificates() {
        return getFieldAs(TBSCertListField.REVOKED_CERTIFICATES, RevokedCertificates.class);
    }

    public void setRevokedCertificates(RevokedCertificates revokedCertificates) {
        setFieldAs(TBSCertListField.REVOKED_CERTIFICATES, revokedCertificates);
    }

    public Extensions getCrlExtensions() {
        return getFieldAs(TBSCertListField.CRL_EXTENSIONS, Extensions.class);
    }

    public void setCrlExtensions(Extensions crlExtensions) {
        setFieldAs(TBSCertListField.CRL_EXTENSIONS, crlExtensions);
    }
}
