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
package org.apache.kerby.kerberos.kerb.client;

import org.apache.kerby.kerberos.kerb.client.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.crypto.util.Nonce;

public class KrbContext {

    private String kdcRealm;
    private KrbConfig config;
    private String kdcHost;
    private short kdcPort;
    private long timeout = 10L;
    private PreauthHandler preauthHandler;

    public void init(KrbConfig config) {
        this.config = config;
        preauthHandler = new PreauthHandler();
        preauthHandler.init(this);
    }

    public String getKdcHost() {
        if (kdcHost != null) {
            return kdcHost;
        }
        return config.getKdcHost();
    }

    public void setKdcHost(String kdcHost) {
        this.kdcHost = kdcHost;
    }

    public short getKdcPort() {
        if (kdcPort > 0) {
            return kdcPort;
        }
        return config.getKdcPort();
    }

    public void setKdcPort(short kdcPort) {
        this.kdcPort = kdcPort;
    }

    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }

    public long getTimeout() {
        return this.timeout;
    }

    public KrbConfig getConfig() {
        return config;
    }

    public void setKdcRealm(String realm) {
        this.kdcRealm = realm;
    }

    public String getKdcRealm() {
        if (kdcRealm != null) {
            return kdcRealm;
        }

        return config.getKdcRealm();
    }

    public int generateNonce() {
        return Nonce.value();
    }

    public long getTicketValidTime() {
        return 8 * 60 * 60 * 1000;
    }

    public PreauthHandler getPreauthHandler() {
        return preauthHandler;
    }
}
