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
package org.apache.kerby.kerberos.kdc.server;

import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kdc.identitybackend.LdapIdentityBackend;
import org.apache.kerby.kerberos.kerb.identity.IdentityService;
import org.apache.kerby.kerberos.kerb.server.KdcServer;

/**
 * The mentioned Kerby KDC server implementation
 */
public class KerbyKdcServer extends KdcServer {

    public KerbyKdcServer() {
        super();
    }

    public void init() {
        super.init();
        initIdentityService();
    }

    private static KdcServer server;
    private static final String USAGE = "Usage: " + KerbyKdcServer.class.getSimpleName() + " -start conf-dir working-dir|-stop";

    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println(USAGE);
            return;
        }

        if (args[0].equals("-start")) {
            if (args.length != 3) {
                System.err.println(USAGE);
                return;
            }
            String confDir = args[1];
            String workingDir = args[2];

            //FIXME host and config should be loaded from configuration.
            String serverHost = "localhost";
            short serverPort = 8015;

            server = new KdcServer();
            server.setKdcHost(serverHost);
            server.setKdcTcpPort(serverPort);
            server.init();
            server.start();
            System.out.println("KDC Server(" + KerbyKdcServer.class.getSimpleName() + ") started.");
        } else if (args[0].equals("-stop")) {
            //server.stop();//FIXME can't get the server instance here
            System.out.println("KDC Server stoped.");
        } else {
            System.err.println(USAGE);
        }

    }

    protected void initIdentityService() {
        Config config = getKdcConfig().getBackendConfig();
        IdentityService identityService = new LdapIdentityBackend(config);
        setIdentityService(identityService);
    }
}