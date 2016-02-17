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
package org.apache.kerby.kerberos.kerb.preauth.pkinit;

import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.AlgorithmIdentifiers;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.TrustedCertifiers;
import org.apache.kerby.x509.type.AlgorithmIdentifier;

/*
 *Ref. MIT Krb5 _pkinit_plg_opts
 */
public class PluginOpts {

    // require EKU checking (default is true)
    public boolean requireEku = true;
    // accept secondary EKU (default is false)
    public boolean acceptSecondaryEku = false;
    // allow UPN-SAN instead of pkinit-SAN
    public boolean allowUpn = true;
    // selects DH or RSA based pkinit
    public boolean usingRsa = false;
    // require CRL for a CA (default is false)
    public boolean requireCrlChecking = false;
    // the size of the Diffie-Hellman key the client will attempt to use.
    // The acceptable values are 1024, 2048, and 4096. The default is 1024.
    public int dhMinBits = 1024;

    public AlgorithmIdentifiers createSupportedCMSTypes() throws KrbException {
        AlgorithmIdentifiers cmsAlgorithms = new AlgorithmIdentifiers();
        AlgorithmIdentifier des3Alg = new AlgorithmIdentifier();

        /* krb5_data des3oid = {0, 8, "\x2A\x86\x48\x86\xF7\x0D\x03\x07" };*/
        String content = "0x06 08 2A 86 48 86 F7 0D 03 07";
        Asn1ObjectIdentifier des3Oid = PkinitCrypto.createOid(content);
        des3Alg.setAlgorithm(des3Oid.getValue());

        cmsAlgorithms.add(des3Alg);

        return cmsAlgorithms;
    }

    public TrustedCertifiers createTrustedCertifiers() {
        TrustedCertifiers trustedCertifiers = new TrustedCertifiers();

        return trustedCertifiers;
    }

    public byte[] createIssuerAndSerial() {
        return null;
    }
}
