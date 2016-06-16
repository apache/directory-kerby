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
package org.apache.kerby.kerberos.kerb.common;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.io.IOUtils;
import org.apache.kerby.util.Base64;

public class PublicKeyReader {

    public static PublicKey loadPublicKey(InputStream in) throws Exception {
        byte[] keyBytes = IOUtils.toByteArray(in);
        
        try {
            return loadPublicKey(keyBytes);
        } catch (InvalidKeySpecException ex) {
            // It might be a Certificate and not a PublicKey...
            Certificate cert = 
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(keyBytes));
            return cert.getPublicKey();
        }
    }


    public static PublicKey loadPublicKey(byte[] publicKeyBytes) throws Exception {
        String pubKey = new String(publicKeyBytes, "UTF-8");
        if (pubKey.startsWith("-----BEGIN PUBLIC KEY-----")) {
            // PEM format
            pubKey = pubKey.replace("-----BEGIN PUBLIC KEY-----", "");
            pubKey = pubKey.replace("-----END PUBLIC KEY-----", "");
            
            Base64 base64 = new Base64();
            byte[] buffer = base64.decode(pubKey.trim());
            
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return keyFactory.generatePublic(keySpec);
        } else {
            // DER format
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            return keyFactory.generatePublic(keySpec);
        }
    }

}
