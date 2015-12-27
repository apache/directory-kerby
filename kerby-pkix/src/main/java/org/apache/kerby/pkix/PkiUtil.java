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
package org.apache.kerby.pkix;

import org.apache.kerby.cms.type.SignedData;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Pki utilities.
 */
public final class PkiUtil {
    private PkiUtil() {

    }

    public static byte[] getSignedData(PrivateKey privateKey,
                                       X509Certificate certificate, byte[] dataToSign,
                                       String eContentType) throws PkiException {

        /**
         * TO DO
         */
        return null;
    }

    /**
     * Validates a CMS SignedData using the public key corresponding to the private
     * key used to sign the structure.
     *
     * @param signedData
     * @return true if the signature is valid.
     * @throws PkiException
     */
    public static boolean validateSignedData(SignedData signedData) throws PkiException {
        /**
         * TO DO
         */
        return false;
    }
}
