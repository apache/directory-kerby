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
package org.apache.kerby.kerberos.kerb.admin;

import org.apache.kerby.KOptions;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;

import java.io.File;
import java.util.List;

/**
 * Server side admin facilities.
 */
public class Kadmin {

    private KdcConfig kdcConfig;
    private Config backendConfig;
    private IdentityBackend backend;

    protected Kadmin(KdcConfig kdcConfig, Config backendConfig) {
        this.kdcConfig = kdcConfig;
        this.backendConfig = backendConfig;
        this.backend = KadminUtil.getBackend(backendConfig);
    }

    public static Kadmin getInstance(File confDir) throws KrbException {
        return KadminUtil.createKadmin(confDir);
    }

    public KdcConfig getKdcConfig() {
        return kdcConfig;
    }

    public Config getBackendConfig() {
        return backendConfig;
    }

    /**
     * Get identity backend.
     * @return IdentityBackend
     */
    public IdentityBackend getIdentityBackend() {
        return backend;
    }

    public void addPrincipal(String principal, KOptions kOptions)
        throws KrbException {
        KrbIdentity identity = KadminUtil.createIdentity(principal, kOptions);
        List<EncryptionKey> keys = EncryptionUtil.generateKeys(
            kdcConfig.getEncryptionTypes());
        identity.addKeys(keys);
        backend.addIdentity(identity);
    }

    public void addPrincipal(String principal, String password, KOptions kOptions)
        throws KrbException {
        KrbIdentity identity = KadminUtil.createIdentity(principal, kOptions);
        List<EncryptionKey> keys = EncryptionUtil.generateKeys(principal, password,
            kdcConfig.getEncryptionTypes());
        identity.addKeys(keys);
        backend.addIdentity(identity);
    }

    public void exportKeytab(File keytabFile, String principalName)
        throws KrbException {

        //Get Identity
        KrbIdentity identity = backend.getIdentity(principalName);
        if (identity == null) {
            throw new KrbException("Can not find the identity for pincipal " +
                    principalName);
        }

        KadminUtil.exportKeytab(keytabFile, identity);
    }

    public void removeKeytabEntriesOf(File keytabFile, String principalName)
        throws KrbException {
        KadminUtil.removeKeytabEntriesOf(keytabFile, principalName);
    }

    public void removeKeytabEntriesOf(File keytabFile,
                                      String principalName, int kvno)
        throws KrbException {
        KadminUtil.removeKeytabEntriesOf(keytabFile, principalName, kvno);
    }

    public void removeOldKeytabEntriesOf(File keytabFile, String principalName)
        throws KrbException {
        KadminUtil.removeOldKeytabEntriesOf(keytabFile, principalName);
    }

    public void deletePrincipal(String principal) throws KrbException {
        backend.deleteIdentity(principal);
    }

    public void modifyPrincipal(String principal, KOptions kOptions)
        throws KrbException {
        KrbIdentity identity = backend.getIdentity(principal);
        if (identity == null) {
            throw new KrbException("Principal \"" +
                identity.getPrincipalName() + "\" does not exist.");
        }
        KadminUtil.updateIdentity(identity, kOptions);
        backend.updateIdentity(identity);
    }

    public void renamePrincipal(String oldPrincipalName, String newPrincipalName)
        throws KrbException {

        KrbIdentity oldIdentity = backend.getIdentity(newPrincipalName);
        if(oldIdentity != null) {
            throw new KrbException("Principal \"" +
                oldIdentity.getPrincipalName() + "\" is already exist.");
        }
        KrbIdentity identity = backend.getIdentity(oldPrincipalName);
        if (identity == null) {
            throw new KrbException("Principal \"" +
                oldPrincipalName + "\" does not exist.");
        }
        backend.deleteIdentity(oldPrincipalName);

        identity.setPrincipalName(newPrincipalName);
        identity.setPrincipal(new PrincipalName(newPrincipalName));
        backend.addIdentity(identity);
    }

    public KrbIdentity getPrincipal(String principalName) throws KrbException {
        KrbIdentity identity = backend.getIdentity(principalName);
        return identity;
    }

    public List<String> getPrincipals() throws KrbException {
        List<String> principalNames = backend.getIdentities();
        return principalNames;
    }

    public void updatePassword(String principal, String password)
        throws KrbException {
        KrbIdentity identity = backend.getIdentity(principal);
        if (identity == null) {
            throw new KrbException("Principal " + principal +
                "was not found. Please check the input and try again");
        }
        List<EncryptionKey> keys = EncryptionUtil.generateKeys(principal, password,
            kdcConfig.getEncryptionTypes());
        identity.addKeys(keys);

        backend.updateIdentity(identity);
    }

    public void updateKeys(String principal) throws KrbException {
        KrbIdentity identity = backend.getIdentity(principal);
        if (identity == null) {
            throw new KrbException("Principal " + principal +
                "was not found. Please check the input and try again");
        }
        List<EncryptionKey> keys = EncryptionUtil.generateKeys(
            kdcConfig.getEncryptionTypes());
        identity.addKeys(keys);
        backend.updateIdentity(identity);
    }
}
