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

public interface CheckSumTypeHandler extends CryptoTypeHandler {

    int confounderSize();

    CheckSumType cksumType();

    int computeSize(); // allocation size for checksum computation

    int outputSize(); // possibly truncated output size

    boolean isSafe();

    int cksumSize();

    int keySize();

    byte[] checksum(byte[] data) throws KrbException;

    byte[] checksum(byte[] data, int start, int len) throws KrbException;

    boolean verify(byte[] data, byte[] checksum) throws KrbException;

    boolean verify(byte[] data, int start, int len, byte[] checksum) throws KrbException;

    byte[] checksumWithKey(byte[] data,
                                  byte[] key, int usage) throws KrbException;

    byte[] checksumWithKey(byte[] data, int start, int len,
                                  byte[] key, int usage) throws KrbException;

    boolean verifyWithKey(byte[] data,
                                 byte[] key, int usage, byte[] checksum) throws KrbException;
}
