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
package org.apache.kerby.kerberos.kerb.codec.pac;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.CheckSumHandler;
import org.apache.kerby.kerberos.kerb.spec.common.CheckSum;
import org.apache.kerby.kerberos.kerb.spec.common.KeyUsage;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

public class Pac {

    private PacLogonInfo logonInfo;
    private PacCredentialType credentialType;
    private PacSignature serverSignature;
    private PacSignature kdcSignature;

    public Pac(byte[] data, byte[] key) throws KrbException {
        byte[] checksumData = data.clone();
        try {
            PacDataInputStream pacStream = new PacDataInputStream(new DataInputStream(
                    new ByteArrayInputStream(data)));

            if(data.length <= 8)
                throw new IOException("pac.token.empty");

            int bufferCount = pacStream.readInt();
            int version = pacStream.readInt();

            if(version != PacConstants.PAC_VERSION) {
                Object[] args = new Object[]{version};
                throw new IOException("pac.version.invalid");
            }

            for(int bufferIndex = 0; bufferIndex < bufferCount; bufferIndex++) {
                int bufferType = pacStream.readInt();
                int bufferSize = pacStream.readInt();
                long bufferOffset = pacStream.readLong();
                byte[] bufferData = new byte[bufferSize];
                System.arraycopy(data, (int)bufferOffset, bufferData, 0, bufferSize);

                switch (bufferType) {
                case PacConstants.LOGON_INFO:
                    // PAC Credential Information
                    logonInfo = new PacLogonInfo(bufferData);
                    break;
                case PacConstants.CREDENTIAL_TYPE:
                    // PAC Credential Type
                    credentialType = new PacCredentialType(bufferData);
                    break;
                case PacConstants.SERVER_CHECKSUM:
                    // PAC Server Signature
                    serverSignature = new PacSignature(bufferData);
                    // Clear signature from checksum copy
                    for(int i = 0; i < bufferSize; i++)
                        checksumData[(int)bufferOffset + 4 + i] = 0;
                    break;
                case PacConstants.PRIVSVR_CHECKSUM:
                    // PAC KDC Signature
                    kdcSignature = new PacSignature(bufferData);
                    // Clear signature from checksum copy
                    for(int i = 0; i < bufferSize; i++)
                        checksumData[(int)bufferOffset + 4 + i] = 0;
                    break;
                default:
                }
            }
        } catch(IOException e) {
            throw new KrbException("pac.token.malformed", e);
        }

        CheckSum checksum = new CheckSum(serverSignature.getType(), serverSignature.getChecksum());
        if (! CheckSumHandler.verifyWithKey(checksum, checksumData, key, KeyUsage.APP_DATA_CKSUM)) {
            throw new KrbException("Check sum verifying failed");
        }
    }

    public PacLogonInfo getLogonInfo() {
        return logonInfo;
    }

    public PacCredentialType getCredentialType() {
        return credentialType;
    }

    public PacSignature getServerSignature() {
        return serverSignature;
    }

    public PacSignature getKdcSignature() {
        return kdcSignature;
    }
}
