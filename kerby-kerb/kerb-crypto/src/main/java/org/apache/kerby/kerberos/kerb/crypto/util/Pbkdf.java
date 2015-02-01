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
package org.apache.kerby.kerberos.kerb.crypto.util;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;

public class Pbkdf {

    public static byte[] PBKDF2(char[] secret, byte[] salt,
                                   int count, int keySize) throws GeneralSecurityException {

        PBEKeySpec ks = new PBEKeySpec(secret, salt, count, keySize * 8);
        SecretKeyFactory skf =
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey key = skf.generateSecret(ks);
        byte[] result = key.getEncoded();

        return result;
    }
}
