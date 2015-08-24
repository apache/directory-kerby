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
package org.apache.kerby.kerberos.kerb.provider;

import org.apache.kerby.kerberos.kerb.KrbException;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;

/**
 * A PKI certificate and key loader.
 */
public interface PkiLoader {

    /**
     * Load certificates from a cert file.
     * @param certFile The cert file
     * @return The certificates
     * @throws KrbException e
     */
    List<Certificate> loadCerts(String certFile) throws KrbException;

    /**
     * Load certificates from an input stream.
     * @param inputStream The input stream
     * @return The certificates
     * @throws KrbException e
     */
    List<Certificate> loadCerts(InputStream inputStream) throws KrbException;

    /**
     * Load private key from a key file with a password.
     * @param keyFile The key file
     * @param password The password
     * @return private key
     * @throws KrbException e
     */
    PrivateKey loadPrivateKey(String keyFile,
                                    String password) throws KrbException;

    /**
     * Load a private key from input stream with a password.
     * @param inputStream The input stream
     * @param password The password
     * @return private key
     * @throws KrbException e
     */
    PrivateKey loadPrivateKey(InputStream inputStream,
                                    String password) throws KrbException;

}
