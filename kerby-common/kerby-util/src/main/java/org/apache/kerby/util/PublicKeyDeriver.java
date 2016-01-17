/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/trunk/src/java/org/apache/commons/ssl/Certificates.java $
 * $Revision: 121 $
 * $Date: 2007-11-13 21:26:57 -0800 (Tue, 13 Nov 2007) $
 *
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */
package org.apache.kerby.util;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Utility class for deriving a public key from a given private key.
 */
public class PublicKeyDeriver {

    /**
     * Utility method for deriving a public key from a given private key.
     *
     * @param key private key for which we need a public key (DSA or RSA).
     * @return the corresponding public key
     * @throws java.security.GeneralSecurityException if it didn't work
     */
    public static PublicKey derivePublicKey(PrivateKey key) throws GeneralSecurityException {
        if (key instanceof DSAPrivateKey) {
            DSAPrivateKey dsaKey = (DSAPrivateKey) key;
            DSAParams keyParams = dsaKey.getParams();
            BigInteger g = keyParams.getG();
            BigInteger p = keyParams.getP();
            BigInteger q = keyParams.getQ();
            BigInteger x = dsaKey.getX();
            BigInteger y = q.modPow(x, p);
            DSAPublicKeySpec keySpec = new DSAPublicKeySpec(y, p, q, g);
            return KeyFactory.getInstance("DSA").generatePublic(keySpec);
        } else if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;
            BigInteger modulus = rsaKey.getModulus();
            BigInteger exponent = rsaKey.getPublicExponent();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } else {
            throw new KeyException("Private key was not a DSA or RSA key");
        }
    }
}

