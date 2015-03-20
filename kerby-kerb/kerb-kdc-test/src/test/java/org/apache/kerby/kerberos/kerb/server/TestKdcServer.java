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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.keytab.KeytabEntry;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

public class TestKdcServer extends SimpleKdcServer {

    /**
     * Prepare KDC configuration for the test.
     */
    protected void prepareKdcConfig() {
        KdcConfig kdcConfig = getKdcConfig();

        kdcConfig.setString(KdcConfigKey.KDC_HOST, "localhost");
        kdcConfig.setInt(KdcConfigKey.KDC_TCP_PORT, 8018);
        kdcConfig.setString(KdcConfigKey.KDC_DOMAIN, "test.com");
        kdcConfig.setString(KdcConfigKey.KDC_REALM, "TEST.COM");
    }

    @Override
    public void init() {
        super.init();

        prepareKdcConfig();
    }

    public void createKrbtgtPrincipal() {
        createPrincipals("krbtgt");
    }

    public String getKdcRealm() {
        return getKdcConfig().getKdcRealm();
    }

    public synchronized void createPrincipal(String principal, String password) {
        KrbIdentity identity = new KrbIdentity(principal);
        List<EncryptionType> encTypes = getKdcConfig().getEncryptionTypes();
        List<EncryptionKey> encKeys = null;
        try {
            encKeys = EncryptionUtil.generateKeys(fixPrincipal(principal), password, encTypes);
        } catch (KrbException e) {
            throw new RuntimeException("Failed to generate encryption keys", e);
        }
        identity.addKeys(encKeys);
        getIdentityService().addIdentity(identity);
    }

    public void setBackend(IdentityBackend backend) {
        super.setBackend(backend);
    }


    public void createPrincipals(String ... principals) {
        String passwd;
        for (String principal : principals) {
            passwd = UUID.randomUUID().toString();
            createPrincipal(fixPrincipal(principal), passwd);
        }
    }

    private String fixPrincipal(String principal) {
        if (! principal.contains("@")) {
            principal += "@" + getKdcRealm();
        }
        return principal;
    }

    public void exportPrincipals(File keytabFile) throws IOException {
        Keytab keytab = new Keytab();

        List<String> principals = getIdentityService().getIdentities(-1, -1);
        for (String pn : principals) {
            KrbIdentity identity = getIdentityService().getIdentity(pn);
            PrincipalName principal = identity.getPrincipal();
            KerberosTime timestamp = new KerberosTime();
            for (EncryptionType encType : identity.getKeys().keySet()) {
                EncryptionKey ekey = identity.getKeys().get(encType);
                int keyVersion = ekey.getKvno();
                keytab.addEntry(new KeytabEntry(principal, timestamp, keyVersion, ekey));
            }
        }

        keytab.store(keytabFile);
    }
}