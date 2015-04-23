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
package org.apache.kerby.kerberos.kerb.crypto;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;

public interface EncTypeHandler extends CryptoTypeHandler {

    EncryptionType eType();

    int keyInputSize();

    int keySize();

    int confounderSize();

    int checksumSize();

    int prfSize();

    byte[] prf(byte[] key, byte[] seed) throws KrbException;

    int paddingSize();

    byte[] str2key(String string,
                          String salt, byte[] param) throws KrbException;

    byte[] random2Key(byte[] randomBits) throws KrbException;

    CheckSumType checksumType();

    byte[] encrypt(byte[] data, byte[] key, int usage)
        throws KrbException;

    byte[] encrypt(byte[] data, byte[] key, byte[] ivec,
        int usage) throws KrbException;

    byte[] decrypt(byte[] cipher, byte[] key, int usage)
        throws KrbException;

    byte[] decrypt(byte[] cipher, byte[] key, byte[] ivec,
        int usage) throws KrbException;
}
