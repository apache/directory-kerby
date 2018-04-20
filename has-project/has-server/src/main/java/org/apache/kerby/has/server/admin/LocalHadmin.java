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

import org.apache.kerby.has.common.Hadmin;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.server.HasServer;
import org.apache.kerby.has.server.web.HostRoleType;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcSetting;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;
import org.apache.kerby.kerberos.kerb.server.ServerSetting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class LocalHadmin implements Hadmin {
    public static final Logger LOG = LoggerFactory.getLogger(LocalHadmin.class);

    private final ServerSetting serverSetting;
    private LocalKadmin kadmin;

    public LocalHadmin(HasServer hasServer) throws KrbException {
        if (hasServer.getKdcServer() == null) {
            throw new RuntimeException("Could not get HAS KDC server, please start KDC first.");
        }
        this.serverSetting = hasServer.getKdcServer().getKdcSetting();

        kadmin = new LocalKadminImpl(serverSetting);
    }

    /**
     * Construct with prepared conf dir.
     *
     * @param confDir The path of conf dir
     * @throws KrbException e
     */
    public LocalHadmin(File confDir) throws KrbException {
        KdcConfig tmpKdcConfig = KdcUtil.getKdcConfig(confDir);
        if (tmpKdcConfig == null) {
            tmpKdcConfig = new KdcConfig();
        }

        BackendConfig tmpBackendConfig = KdcUtil.getBackendConfig(confDir);
        if (tmpBackendConfig == null) {
            tmpBackendConfig = new BackendConfig();
        }

        this.serverSetting = new KdcSetting(tmpKdcConfig, tmpBackendConfig);
        kadmin = new LocalKadminImpl(serverSetting);
    }

    @Override
    public List<String> addPrincByRole(String host, String role) throws HasException {
        List<String> result = new ArrayList<>();
        String realm = "/" + host + "@" + kadmin.getKdcConfig().getKdcRealm();
        String[] princs = HostRoleType.valueOf(role).getPrincs();
        if (princs == null) {
            LOG.error("Cannot find the role of : " + role);
            result.add("Cannot find the role of : " + role);
            return result;
        }
        for (String princ : princs) {
            try {
                kadmin.addPrincipal(princ + realm);
                LOG.info("Success to add princ: " + princ + realm);
                result.add("Success to add princ: " + princ + realm);
            } catch (KrbException e) {
                String message = e.getMessage();
                LOG.info(message);
                result.add(message);
            }
        }
        return result;
    }

    @Override
    public File getKeytabByHostAndRole(String host, String role) throws HasException {
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

    @Override
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
