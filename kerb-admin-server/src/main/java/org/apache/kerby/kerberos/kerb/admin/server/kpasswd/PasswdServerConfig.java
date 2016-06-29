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
package org.apache.kerby.kerberos.kerb.admin.server.kpasswd;


import org.apache.kerby.kerberos.kerb.common.Krb5Conf;

/**
 * Kerb KDC side configuration API.
 */
public class PasswdServerConfig extends Krb5Conf {
    private static final String KDCDEFAULT = "passwddefaults";

    public boolean enableDebug() {
        return getBoolean(PasswdServerConfigKey.KRB_DEBUG, true, KDCDEFAULT);
    }

    public String getPasswdServiceName() {
        return getString(PasswdServerConfigKey.ADMIN_SERVICE_NAME, true, KDCDEFAULT);
    }

    public String getPasswdHost() {
        return getString(PasswdServerConfigKey.ADMIN_HOST, true, KDCDEFAULT);
    }

    public int getPasswdPort() {
        Integer passwdPort = getInt(PasswdServerConfigKey.ADMIN_PORT, true, KDCDEFAULT);
        if (passwdPort != null && passwdPort > 0) {
            return passwdPort.intValue();
        }
        return -1;
    }

    public int getPasswdTcpPort() {
        Integer passwdTcpPort = getInt(PasswdServerConfigKey.ADMIN_TCP_PORT, true, KDCDEFAULT);
        if (passwdTcpPort != null && passwdTcpPort > 0) {
            return passwdTcpPort.intValue();
        }
        return getPasswdPort();
    }

    /**
     * Is to allow TCP for KDC
     * @return true to allow TCP, false otherwise
     */
    public Boolean allowTcp() {
        return getBoolean(PasswdServerConfigKey.ADMIN_ALLOW_TCP, true, KDCDEFAULT)
                || getInt(PasswdServerConfigKey.ADMIN_TCP_PORT, true, KDCDEFAULT) != null
            || getInt(PasswdServerConfigKey.ADMIN_PORT, false, KDCDEFAULT) != null;
    }

    /**
     * Is to allow UDP for KDC
     * @return true to allow UDP, false otherwise
     */
    public Boolean allowUdp() {
        return getBoolean(PasswdServerConfigKey.ADMIN_ALLOW_UDP, true, KDCDEFAULT)
                || getInt(PasswdServerConfigKey.ADMIN_UDP_PORT, true, KDCDEFAULT) != null
            || getInt(PasswdServerConfigKey.ADMIN_PORT, false, KDCDEFAULT) != null;
    }

    public int getPasswdUdpPort() {
        Integer passwdUdpPort = getInt(PasswdServerConfigKey.ADMIN_UDP_PORT, true, KDCDEFAULT);
        if (passwdUdpPort != null && passwdUdpPort > 0) {
            return passwdUdpPort.intValue();
        }
        return getPasswdPort();
    }

    public String getPasswdRealm() {
        return getString(PasswdServerConfigKey.ADMIN_REALM, true, KDCDEFAULT);
    }

    public String getPasswdDomain() {
        return getString(PasswdServerConfigKey.ADMIN_DOMAIN, true, KDCDEFAULT);
    }
}
