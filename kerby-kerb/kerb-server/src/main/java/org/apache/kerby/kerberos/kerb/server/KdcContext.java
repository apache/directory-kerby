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
package org.apache.kerby.kerberos.kerb.server;

import org.apache.kerby.kerberos.kerb.identity.IdentityService;
import org.apache.kerby.kerberos.kerb.server.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.server.replay.ReplayCheckService;

import java.util.List;

public class KdcContext {
    private KdcConfig config;
    private List<String> supportedKdcRealms;
    private String kdcRealm;
    private IdentityService identityService;
    private ReplayCheckService replayCache;
    private PreauthHandler preauthHandler;

    public void init(KdcConfig config) {
        this.config = config;
    }

    public KdcConfig getConfig() {
        return config;
    }

    public void setPreauthHandler(PreauthHandler preauthHandler) {
        this.preauthHandler = preauthHandler;
    }

    public PreauthHandler getPreauthHandler() {
        return this.preauthHandler;
    }

    public List<String> getSupportedKdcRealms() {
        return supportedKdcRealms;
    }

    public void setSupportedKdcRealms(List<String> supportedKdcRealms) {
        this.supportedKdcRealms = supportedKdcRealms;
    }

    public void setKdcRealm(String realm) {
        this.kdcRealm = realm;
    }

    public String getServerRealm() {
        return config.getKdcRealm();
    }

    public String getKdcRealm() {
        if (kdcRealm != null) {
            return kdcRealm;
        }
        return config.getKdcRealm();
    }

    public void setReplayCache(ReplayCheckService replayCache) {
        this.replayCache = replayCache;
    }

    public ReplayCheckService getReplayCache() {
        return replayCache;
    }

    public void setIdentityService(IdentityService identityService) {
        this.identityService = identityService;
    }


    public IdentityService getIdentityService() {
        return identityService;
    }
}
