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
package org.apache.kerby.kerberos.kdc;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.server.KdcServer;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;

import java.io.File;
import java.util.List;
import java.util.UUID;

/**
 * The mentioned Kerby KDC server implementation.
 */
public class KerbyKdcServer extends KdcServer {
    private static KerbyKdcServer server;

    private static final String USAGE = "Usage: " +
            KerbyKdcServer.class.getSimpleName() +
            " -start conf-dir working-dir|-start|-stop";

    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println(USAGE);
            return;
        }

        if (args[0].equals("-start")) {
            String confDir;
            String workDir;
            if(args.length == 1) {
                confDir = "/etc/kerby/";
                workDir = "/tmp/";
            } else if (args.length == 3) {
                confDir = args[1];
                workDir = args[2];
            } else {
                System.err.println(USAGE);
                return;
            }
            server = new KerbyKdcServer();
            server.setWorkDir(new File(workDir));
            server.setConfDir(new File(confDir));
            server.init();

            server.createPrincipals("krbtgt");

            server.start();
            System.out.println("KDC started.");
        } else if (args[0].equals("-stop")) {
            //server.stop();//FIXME can't get the server instance here
            System.out.println("KDC Server stopped.");
        } else {
            System.err.println(USAGE);
        }
    }

    //create some principal for test
    private void createPrincipal(String principal, String password) {
        KrbIdentity identity = new KrbIdentity(fixPrincipal(principal));
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

    private void createPrincipals(String ... principals) {
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
}