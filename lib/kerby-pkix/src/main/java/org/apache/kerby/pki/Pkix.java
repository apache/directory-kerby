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
package org.apache.kerby.pki;

import org.apache.commons.ssl.PKCS8Key;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class Pkix {

    public static List<Certificate> getCerts(String certFile) throws IOException, CertificateException {
        InputStream is = new FileInputStream(new File(certFile));
        return getCerts(is);
    }

    public static List<Certificate> getCerts(InputStream inputStream) throws IOException, CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certs =
                (Collection<? extends Certificate>) certFactory.generateCertificates(inputStream);

        return new ArrayList<Certificate>(certs);
    }

    public static PrivateKey getPrivateKey(String keyFile, String password) throws IOException, GeneralSecurityException {
        InputStream in = new FileInputStream("/path/to/pkcs8_private_key.der");
        return getPrivateKey(in, password);
    }

    public static PrivateKey getPrivateKey(InputStream inputStream, String password) throws GeneralSecurityException, IOException {
        if (password == null) {
            password = "";
        }
        // If the provided InputStream is encrypted, we need a password to decrypt
        // it. If the InputStream is not encrypted, then the password is ignored
        // (can be null).  The InputStream can be DER (raw ASN.1) or PEM (base64).
        PKCS8Key pkcs8 = new PKCS8Key(inputStream, password.toCharArray());

        // If an unencrypted PKCS8 key was provided, then this actually returns
        // exactly what was originally passed inputStream (with no changes).  If an OpenSSL
        // key was provided, it gets reformatted as PKCS #8 first, and so these
        // bytes will still be PKCS #8, not OpenSSL.
        byte[] decrypted = pkcs8.getDecryptedBytes();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decrypted);

        // A Java PrivateKey object is born.
        PrivateKey pk = null;
        if (pkcs8.isDSA()) {
            pk = KeyFactory.getInstance("DSA").generatePrivate(spec);
        }
        else if (pkcs8.isRSA()) {
            pk = KeyFactory.getInstance("RSA").generatePrivate(spec);
        }

        // For lazier types:
        pk = pkcs8.getPrivateKey();

        return pk;
    }
}
