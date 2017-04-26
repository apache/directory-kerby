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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CertificateHelper {
    private static final Logger LOG = LoggerFactory.getLogger(CertificateHelper.class);

    public static List<Certificate> loadCerts(String filename) throws KrbException {
        
        File file = new File(filename);
        InputStream res = null;
        if (file.isFile()) {
            try {
                res = Files.newInputStream(file.toPath());
            } catch (IOException e) {
                LOG.error("Can't load cert, file not found. " + e);
            }
        } else {
            res = CertificateHelper.class.getClassLoader().getResourceAsStream(filename);
        }
        
        return loadCerts(res);
    }

    public static List<Certificate> loadCerts(InputStream inputStream) throws KrbException {
        CertificateFactory certFactory = null;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs = (Collection<? extends Certificate>)
                    certFactory.generateCertificates(inputStream);
            return new ArrayList<Certificate>(certs);
        } catch (CertificateException e) {
            throw new KrbException("Failed to load certificates", e);
        }
    }
}
