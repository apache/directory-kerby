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

import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;

public class PkinitIdenity {

    public static void processIdentityOption(IdentityOpts identityOpts, String value) {
        IdentityType idType = IdentityType.NONE;
        String residual = null;
        if (value.contains(":")) {
            if (value.startsWith("FILE:")) {
                idType = IdentityType.FILE;
            } else if (value.startsWith("PKCS11:")) {
                idType = IdentityType.PKCS11;
            } else if (value.startsWith("PKCS12:")) {
                idType = IdentityType.PKCS12;
            } else if (value.startsWith("DIR:")) {
                idType = IdentityType.DIR;
            } else if (value.startsWith("ENV:")) {
                idType = IdentityType.ENVVAR;
            } else {
                throw new RuntimeException("Invalid Identity option format: " + value);
            }
        } else {
            residual = value;
            idType = IdentityType.FILE;
        }

        identityOpts.idType = idType;
        switch (idType) {
            case ENVVAR:
                processIdentityOption(identityOpts, System.getenv(residual));
                break;
            case FILE:
                parseFileOption(identityOpts, residual);
                break;
            case PKCS11:
                parsePkcs11Option(identityOpts, residual);
                break;
            case PKCS12:
                parsePkcs12Option(identityOpts, residual);
                break;
            case DIR:
                identityOpts.certFile = residual;
                break;
        }
    }

    public static void parseFileOption(IdentityOpts identityOpts, String residual) {
        String[] parts = residual.split(",");
        String certName = parts[0];
        String keyName = null;

        if (parts.length > 1) {
            keyName = parts[1];
        }

        identityOpts.certFile = certName;
        identityOpts.keyFile = keyName;
    }

    public static void parsePkcs12Option(IdentityOpts identityOpts, String residual) {
        identityOpts.certFile = residual;
        identityOpts.keyFile = residual;
    }

    public static void parsePkcs11Option(IdentityOpts identityOpts, String residual) {
        // TODO
    }

    public static void loadCerts(IdentityOpts identityOpts, PrincipalName principal) {
        switch (identityOpts.idType) {
            case FILE:
                loadCertsFromFile(identityOpts, principal);
                break;
            case DIR:
                loadCertsFromDir(identityOpts, principal);
                break;
            case PKCS11:
                loadCertsAsPkcs11(identityOpts, principal);
                break;
            case PKCS12:
                loadCertsAsPkcs12(identityOpts, principal);
                break;
        }
    }

    private static void loadCertsAsPkcs12(IdentityOpts identityOpts, PrincipalName principal) {

    }

    private static void loadCertsAsPkcs11(IdentityOpts identityOpts, PrincipalName principal) {

    }

    private static void loadCertsFromDir(IdentityOpts identityOpts, PrincipalName principal) {

    }

    private static void loadCertsFromFile(IdentityOpts identityOpts, PrincipalName principal) {

    }

    public static void initialize(IdentityOpts identityOpts, PrincipalName principal) {

    }

}
