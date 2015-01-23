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
import org.apache.kerby.kerberos.kerb.spec.pa.pkinit.AlgorithmIdentifiers;
import org.apache.kerby.kerberos.kerb.spec.pa.pkinit.TrustedCertifiers;
import org.apache.kerby.kerberos.kerb.spec.x509.AlgorithmIdentifier;

public class PluginOpts {

    // From MIT Krb5 _pkinit_plg_opts

    // require EKU checking (default is true)
    public boolean requireEku = true;
    // accept secondary EKU (default is false)
    public boolean acceptSecondaryEku = false;
    // allow UPN-SAN instead of pkinit-SAN
    public boolean allowUpn = true;
    // selects DH or RSA based pkinit
    public boolean usingRsa = true;
    // require CRL for a CA (default is false)
    public boolean requireCrlChecking = false;
    // the size of the Diffie-Hellman key the client will attempt to use.
    // The acceptable values are 1024, 2048, and 4096. The default is 2048.
    public int dhMinBits = 2048;

    public AlgorithmIdentifiers createSupportedCMSTypes() {
        AlgorithmIdentifiers cmsAlgorithms = new AlgorithmIdentifiers();
        AlgorithmIdentifier des3Alg = new AlgorithmIdentifier();
        cmsAlgorithms.add(des3Alg);

        String oidStr = "DES3-OID";
        Asn1ObjectIdentifier des3Oid = new Asn1ObjectIdentifier(oidStr);
        des3Alg.setAlgorithm(des3Oid);
        des3Alg.setParameters(null);

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
