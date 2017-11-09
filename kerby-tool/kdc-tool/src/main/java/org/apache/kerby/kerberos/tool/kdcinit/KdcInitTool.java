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
package org.apache.kerby.kerberos.tool.kdcinit;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServer;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerConfig;
import org.apache.kerby.util.OSUtil;

import java.io.File;

/**
 * A tool to initialize KDC backend for the first time when setup the KDC.
 */
public class KdcInitTool {
    private LocalKadmin kadmin;
    private static File adminKeytabFile;
    private static File protocolKeytabFile;

    private static  final String USAGE = (OSUtil.isWindows()
            ? "Usage: bin\\kdcinit.cmd" : "Usage: sh bin/kdcinit.sh")
            + " <conf-dir> <keytab-dir>\n"
            + "\tThis tool initializes KDC backend and should only be performed the first time,\n"
            + "\tand the output keytabs should be carefully kept to administrate/kadmin KDC later.\n"
            + "\tExample:\n"
            + "\t\t"
            + (OSUtil.isWindows()
            ? "bin\\kdcinit.cmd" : "sh bin/kdcinit.sh")
            + " conf keytabfolder\n";

    void initKdc(File confDir) throws KrbException {
        kadmin = new LocalKadminImpl(confDir);
        try {
            kadmin.createBuiltinPrincipals();
            kadmin.exportKeytab(adminKeytabFile, kadmin.getKadminPrincipal());
            System.out.println("The keytab for kadmin principal "
                    + " has been exported to the specified file "
                    + adminKeytabFile.getAbsolutePath() + ", please safely keep it, "
                    + "in order to use kadmin tool later");

            // Export protocol keytab file for remote admin tool
            AdminServer adminServer = new AdminServer(confDir);
            AdminServerConfig adminServerConfig = adminServer.getAdminServerConfig();
            String principal = adminServerConfig.getProtocol() + "/"
                + adminServerConfig.getAdminHost() + "@" + adminServerConfig.getAdminRealm();
            kadmin.addPrincipal(principal);
            kadmin.exportKeytab(protocolKeytabFile, principal);
            System.out.println("The keytab for protocol principal "
                    + " has been exported to the specified file "
                    + protocolKeytabFile.getAbsolutePath() + ", please safely keep it, "
                    + "in order to use remote kadmin tool later");
        } finally {
            kadmin.release();
        }
    }

    public static void main(String[] args) throws KrbException {
        if (args.length != 2) {
            System.err.println(USAGE);
            System.exit(1);
        }

        String confDirPath = args[0];
        String keyTabPath = args[1];
        File confDir = new File(confDirPath);
        File keytabDir = new File(keyTabPath);
        adminKeytabFile = new File(keytabDir, "admin.keytab");
        protocolKeytabFile = new File(keytabDir, "protocol.keytab");
        if (!confDir.exists()) {
            System.err.println("The conf-dir is invalid or does not exist.");
            System.exit(2);
        }
        if (keytabDir != null && !keytabDir.exists() && !keytabDir.mkdirs()) {
            System.err.println("Could not create keytab path." + keytabDir);
            System.exit(3);
        }

        if (adminKeytabFile.exists()) {
            System.err.println("The kadmin keytab already exists in " + adminKeytabFile
                    + ", this tool may have been executed already.");
            return;
        }
        if (protocolKeytabFile.exists()) {
            System.err.println("The protocol keytab already exists in " + protocolKeytabFile
                + ", this tool may have been executed already.");
            return;
        }

        KdcInitTool kdcInitTool = new KdcInitTool();

        try {
            kdcInitTool.initKdc(confDir);
        } catch (KrbException e) {
            System.err.println("Errors occurred when initializing the kdc " + e.getMessage());
            System.exit(1);
        }

        System.out.println("Finished initializing the KDC backend");
        System.exit(0);
    }
}
