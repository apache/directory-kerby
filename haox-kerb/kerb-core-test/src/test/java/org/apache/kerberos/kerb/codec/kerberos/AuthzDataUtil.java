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
package org.apache.kerberos.kerb.codec.kerberos;

import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.codec.pac.Pac;
import org.apache.kerberos.kerb.spec.common.AuthorizationData;
import org.apache.kerberos.kerb.spec.common.AuthorizationDataEntry;
import org.apache.kerberos.kerb.spec.common.AuthorizationType;

import java.io.IOException;
import java.util.List;

public class AuthzDataUtil {

    public static Pac getPac(AuthorizationData authzData, byte[] serverKey) throws IOException, KrbException {
        AuthorizationDataEntry ifRelevantAd = null;
        for (AuthorizationDataEntry entry : authzData.getElements()) {
            if (entry.getAuthzType() == AuthorizationType.AD_IF_RELEVANT) {
                ifRelevantAd = entry;
                break;
            }
        }

        if (ifRelevantAd != null) {
            List<AuthorizationDataEntry> entries = decode(ifRelevantAd);
            for (AuthorizationDataEntry entry : entries) {
                if (entry.getAuthzType() == AuthorizationType.AD_WIN2K_PAC) {
                    return decodeAsPac(entry, serverKey);
                }
            }
        }

        return null;
    }

    public static List<AuthorizationDataEntry> decode(AuthorizationDataEntry entry) throws IOException {
        AuthorizationData authzData = new AuthorizationData();
        authzData.decode(entry.getAuthzData());
        return authzData.getElements();
    }

    public static Pac decodeAsPac(AuthorizationDataEntry entry, byte[] key) throws IOException, KrbException {
        if (entry.getAuthzType() != AuthorizationType.AD_WIN2K_PAC) {
            throw new IllegalArgumentException("Not AD_WIN2K_PAC type: " + entry.getAuthzType().name());
        }

        return new Pac(entry.getAuthzData(), key);
    }
}
