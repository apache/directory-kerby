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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.CheckSumHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.spec.base.CheckSum;
import org.apache.kerby.kerberos.kerb.spec.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.KeyUsage;

public class CheckSumUtil {

    public static CheckSum makeCheckSum(CheckSumType checkSumType, byte[] input)
        throws KrbException {
        return CheckSumHandler.checksum(checkSumType, input);
    }

    public static CheckSum makeCheckSumWithKey(CheckSumType checkSumType, byte[] input,
                                               EncryptionKey key, KeyUsage usage)
        throws KrbException {
        if (checkSumType == CheckSumType.NONE) {
            EncTypeHandler handler = EncryptionHandler.getEncHandler(key.getKeyType());
            checkSumType = handler.checksumType();
        }
        return CheckSumHandler.checksumWithKey(checkSumType, input, key.getKeyData(), usage);
    }
}