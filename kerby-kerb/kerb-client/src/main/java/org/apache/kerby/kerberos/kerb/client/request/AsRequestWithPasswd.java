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
package org.apache.kerby.kerberos.kerb.client.request;

import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;

public class AsRequestWithPasswd extends AsRequest {

    public AsRequestWithPasswd(KrbContext context) {
        super(context);

        setAllowedPreauth(PaDataType.ENC_TIMESTAMP);
    }

    public String getPassword() {
        return getKrbOptions().getStringOption(KrbOption.USER_PASSWD);
    }

    @Override
    public EncryptionKey getClientKey() throws KrbException {
        if (super.getClientKey() == null) {
            EncryptionKey tmpKey = EncryptionHandler.string2Key(getClientPrincipal().getName(),
                    getPassword(), getChosenEncryptionType());
            setClientKey(tmpKey);
        }
        return super.getClientKey();
    }
}
