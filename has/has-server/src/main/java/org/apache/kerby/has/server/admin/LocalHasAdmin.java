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
package org.apache.kerby.has.server.admin;

import org.apache.kerby.has.common.HasAdmin;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.has.server.HasServer;
import org.apache.kerby.has.server.web.HostRoleType;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.request.KrbIdentity;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcSetting;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;
import org.apache.kerby.kerberos.kerb.server.ServerSetting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class LocalHasAdmin implements HasAdmin {
    public static final Logger LOG = LoggerFactory.getLogger(LocalHasAdmin.class);

    private final ServerSetting serverSetting;
    private File confDir;

    public LocalHasAdmin(HasServer hasServer) throws KrbException {
        if (hasServer.getKdcServer() == null) {
            throw new RuntimeException("Could not get HAS KDC server, please start KDC first.");
        }
        this.serverSetting = hasServer.getKdcServer().getKdcSetting();
    }

    /**
     * Construct with prepared conf dir.
     *
     * @param confDir The path of conf dir
     * @throws KrbException e
     */
    public LocalHasAdmin(File confDir) throws KrbException {
        this.confDir = confDir;
        KdcConfig tmpKdcConfig = KdcUtil.getKdcConfig(confDir);
        if (tmpKdcConfig == null) {
            tmpKdcConfig = new KdcConfig();
        }

        BackendConfig tmpBackendConfig = KdcUtil.getBackendConfig(confDir);
        if (tmpBackendConfig == null) {
            tmpBackendConfig = new BackendConfig();
        }

        this.serverSetting = new KdcSetting(tmpKdcConfig, tmpBackendConfig);
    }

    @Override
    public List<String> getPrincipals(String exp) throws HasException {
        LocalKadmin kadmin = null;
        try {
            kadmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        List<String> princs = null;
        LOG.info("The value of exp is : " + exp);
        if (exp == null || exp.equals("")) {
            try {
                princs = kadmin.getPrincipals();
            } catch (KrbException e) {
                throw new HasException(e);
            }
        } else {
            try {
                princs = kadmin.getPrincipals(exp);
            } catch (KrbException e) {
                throw new HasException(e);
            }
        }
        return princs;
    }

    @Override
    public void addPrincipal(String principal, String password) throws HasException {
        LocalKadmin kadmin = null;
        try {
            kadmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        if (principal == null) {
            throw new HasException("Value of principal is null.");
        }
        if (password == null || password.equals("")) {
            try {
                kadmin.addPrincipal(principal);
            } catch (KrbException e) {
                throw new HasException(e);
            }
        } else {
            try {
                kadmin.addPrincipal(principal, password);
            } catch (KrbException e) {
                throw new HasException(e);
            }
        }
        LOG.info("Success to add principal :" + principal);
    }

    @Override
    public void deletePrincipal(String principal) throws HasException {
        LocalKadmin kadmin = null;
        try {
            kadmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
             throw new HasException(e);
        }
        if (principal == null) {
            throw new IllegalArgumentException("Value of principal is null.");
        }
        try {
            kadmin.deletePrincipal(principal);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        LOG.info("Success to delete principal :" + principal);
    }

    @Override
    public void renamePrincipal(String oldPrincipal, String newPrincipal) throws HasException {
        LocalKadmin kadmin = null;
        try {
            kadmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        try {
            kadmin.renamePrincipal(oldPrincipal, newPrincipal);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        LOG.info("Success to rename principal : \"" + oldPrincipal
                + "\" to \"" + newPrincipal + "\".");
    }

    @Override
    public void changePassword(String principal,
                               String newPassword) throws HasException {
        LocalKadmin kadmin;
        try {
            kadmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        try {
            kadmin.changePassword(principal, newPassword);
        } catch (KrbException e) {
            throw new HasException(e);
        }
    }

    @Override
    public void updateKeys(String principal) throws HasException {
        LocalKadmin kadmin;
        try {
            kadmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        try {
            kadmin.updateKeys(principal);
        } catch (KrbException e) {
            throw new HasException(e);
        }
    }

    @Override
    public String addPrincByRole(String host, String role) throws HasException {
        StringBuilder result = new StringBuilder();
        LocalKadmin kAdmin;
        try {
            kAdmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        String realm = "/" + host + "@" + kAdmin.getKdcConfig().getKdcRealm();
        String[] principalArray = HostRoleType.valueOf(role).getPrincs();
        if (principalArray == null) {
            LOG.error("Cannot find the role: " + role);
            return "Cannot find the role: " + role;
        }
        for (String principal : principalArray) {
            try {
                kAdmin.addPrincipal(principal + realm);
                LOG.info("Added principal: " + principal + realm);
                result.append("Added principal: ");
                result.append(principal);
                result.append(realm);
                result.append("\n");
            } catch (KrbException e) {
                LOG.info(e.toString());
                result.append(e.toString());
                result.append("\n");
            }
        }
        return result.toString();
    }

    @Override
    public File getKeytabByHostAndRole(String host, String role) throws HasException {
        LocalKadmin kadmin;
        try {
            kadmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        String realm = "/" + host + "@" + kadmin.getKdcConfig().getKdcRealm();
        File path = new File("/tmp/" + System.currentTimeMillis());
        path.mkdirs();
        File keytab = new File(path, role + "-" + host + ".keytab");
        if (keytab.exists()) {
            keytab.delete();
        }
        String[] princs = HostRoleType.valueOf(role).getPrincs();
        for (String princ : princs) {
            try {
                if (kadmin.getPrincipal(princ + realm) == null) {
                    continue;
                }
            } catch (KrbException e) {
                throw new HasException(e);
            }
            try {
                kadmin.exportKeytab(keytab, princ + realm);
            } catch (KrbException e) {
                throw new HasException(e);
            }
        }
        return keytab;
    }

    public void getKeytabByHostAndRole(String host, String role, File keytab) throws HasException {
        LocalKadmin kadmin;
        try {
            kadmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        String realm = "/" + host + "@" + kadmin.getKdcConfig().getKdcRealm();
        if (keytab.exists()) {
            keytab.delete();
        }
        String[] princs = HostRoleType.valueOf(role).getPrincs();
        for (String princ : princs) {
            try {
                if (kadmin.getPrincipal(princ + realm) == null) {
                    continue;
                }
            } catch (KrbException e) {
                throw new HasException(e);
            }
            try {
                kadmin.exportKeytab(keytab, princ + realm);
                System.out.println("Success to export keytab : " + keytab.getAbsolutePath());
            } catch (KrbException e) {
                throw new HasException(e);
            }
        }
    }

    @Override
    public List<String> getPrincipals() throws HasException {
        LocalKadmin kadmin;
        try {
            kadmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        try {
            return kadmin.getPrincipals();
        } catch (KrbException e) {
            throw new HasException(e);
        }
    }

    public KrbIdentity getPrincipal(String principalName) throws HasException {
        LocalKadmin kadmin;
        KrbIdentity identity;
        try {
            kadmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        try {
            identity = kadmin.getPrincipal(principalName);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        return identity;
    }

    @Override
    public void addPrincipal(String principal) throws HasException {
        LocalKadmin kadmin = null;
        try {
            kadmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        if (principal == null) {
            throw new HasException("Value of principal is null.");
        }
        try {
            kadmin.addPrincipal(principal);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        LOG.info("Success to add principal :" + principal);
    }

    @Override
    public String getHadminPrincipal() {
        return KrbUtil.makeKadminPrincipal(serverSetting.getKdcRealm()).getName();
    }

    /**
     * get size of principal
     */
    @Override
    public int size() throws HasException {
        return this.getPrincipals().size();
    }

    @Override
    public void setEnableOfConf(String isEnable) throws HasException {
        File hasConf = new File(confDir, "has-server.conf");
        if (!hasConf.exists()) {
            System.err.println("has-server.conf is not exists.");
            return;
        }
        try {
            HasUtil.setEnableConf(hasConf, isEnable);
        } catch (IOException e) {
            System.err.println(e.getMessage());
            return;
        }
    }

    @Override
    public void exportKeytab(File keytabFile, String principal)
        throws HasException {
        LocalKadmin kadmin = null;
        try {
            kadmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        try {
            kadmin.exportKeytab(keytabFile, principal);
        } catch (KrbException e) {
            throw new HasException(e);
        }
    }

    @Override
    public void exportKeytab(File keytabFile, List<String> principals)
            throws HasException {
        LocalKadmin kadmin = null;
        try {
            kadmin = new LocalKadminImpl(serverSetting);
        } catch (KrbException e) {
            throw new HasException(e);
        }
        try {
            kadmin.exportKeytab(keytabFile, principals);
        } catch (KrbException e) {
            throw new HasException(e);
        }
    }

    public void getHostRoles() {
        for (HostRoleType role : HostRoleType.values()) {
            System.out.print("\tHostRole: " + role.getName()
                    + ", PrincipalNames: ");
            String[] princs = role.getPrincs();
            for (int j = 0; j < princs.length; j++) {
                System.out.print(princs[j]);
                if (j == princs.length - 1) {
                    System.out.println();
                } else {
                    System.out.print(", ");
                }
            }
        }
    }
}
