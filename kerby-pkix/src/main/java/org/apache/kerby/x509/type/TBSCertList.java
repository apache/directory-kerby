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

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.asn1.type.ExplicitField;
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

    private static final int VERSION = 0;
    private static final int SIGNATURE = 1;
    private static final int ISSUER = 2;
    private static final int THIS_UPDATA = 3;
    private static final int NEXT_UPDATE = 4;
    private static final int REVOKED_CERTIFICATES = 5;
    private static final int CRL_EXTENSIONS = 6;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(VERSION, Asn1Integer.class),
        new Asn1FieldInfo(SIGNATURE, AlgorithmIdentifier.class),
        new Asn1FieldInfo(ISSUER, Name.class),
        new Asn1FieldInfo(THIS_UPDATA, Time.class),
        new Asn1FieldInfo(NEXT_UPDATE, Time.class),
        new Asn1FieldInfo(REVOKED_CERTIFICATES, RevokedCertificates.class),
        new ExplicitField(CRL_EXTENSIONS, 0, Extensions.class)
    };

    public TBSCertList() {
        super(fieldInfos);
    }

    public Asn1Integer getVersion() {
        return getFieldAs(VERSION, Asn1Integer.class);
    }

    public void setVersion(Asn1Integer version) {
        setFieldAs(VERSION, version);
    }

    public AlgorithmIdentifier getSignature() {
        return getFieldAs(SIGNATURE, AlgorithmIdentifier.class);
    }

    public void setSignature(AlgorithmIdentifier signature) {
        setFieldAs(SIGNATURE, signature);
    }

    public Name getIssuer() {
        return getFieldAs(ISSUER, Name.class);
    }

    public void setIssuer(Name issuer) {
        setFieldAs(ISSUER, issuer);
    }

    public Time getThisUpdate() {
        return getFieldAs(THIS_UPDATA, Time.class);
    }

    public void setThisUpdata(Time thisUpdata) {
        setFieldAs(THIS_UPDATA, thisUpdata);
    }

    public Time getNextUpdate() {
        return getFieldAs(NEXT_UPDATE, Time.class);
    }

    public void setNextUpdate(Time nextUpdate) {
        setFieldAs(NEXT_UPDATE, nextUpdate);
    }

    public RevokedCertificates getRevokedCertificates() {
        return getFieldAs(REVOKED_CERTIFICATES, RevokedCertificates.class);
    }

    public void setRevokedCertificates(RevokedCertificates revokedCertificates) {
        setFieldAs(REVOKED_CERTIFICATES, revokedCertificates);
    }

    public Extensions getCrlExtensions() {
        return getFieldAs(CRL_EXTENSIONS, Extensions.class);
    }

    public void setCrlExtensions(Extensions crlExtensions) {
        setFieldAs(CRL_EXTENSIONS, crlExtensions);
    }
}
