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
package org.apache.kerby.kerberos.kerb.admin.server;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.server.kpasswd.PasswdServer;
import org.apache.kerby.kerberos.kerb.admin.server.kpasswd.PasswdServerConfig;
import org.apache.kerby.util.OSUtil;

import java.io.File;

/**
 * A running tool for password server.
 * Allow both tcp and udp.
 * tcp port: 464
 * udp port: 464
 */
public class PasswdServerInit {
    private static final String USAGE = (OSUtil.isWindows()
        ? "Usage: bin\\kpasswdServer.cmd" : "Usage: sh bin/kpasswdServer.sh")
        + " <conf-file>\n"
        + "\tExample:\n"
        + "\t\t"
        + (OSUtil.isWindows()
        ? "bin\\kpasswdServer.cmd" : "sh bin/kpasswdServer.sh")
        + " conf\n";

    public static void main(String[] args) throws Exception {

        if (args.length != 1) {
            System.err.println(USAGE);
            System.exit(1);
        }

        String confDirPath = args[0];
        PasswdServer passwdServer = new PasswdServer(new File(confDirPath));
        PasswdServerConfig passwdServerConfig = passwdServer.getPasswdServerConfig();

        passwdServer.setPasswdHost(passwdServerConfig.getPasswdHost());
        passwdServer.setAllowTcp(true);
        passwdServer.setAllowUdp(true); /**change password protocol allow both tcp and udp*/
        passwdServer.setPasswdServerPort(passwdServerConfig.getPasswdPort());

        try {
            passwdServer.init();
        } catch (KrbException e) {
            System.err.println("Errors occurred when start admin server:  " + e.getMessage());
            System.exit(2);
        }
        passwdServer.start();
        System.out.println("Password server started!");
    }
}

