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
package org.apache.kerby.kerberos.kerb.admin.server.kadmin;

import org.apache.kerby.kerberos.kerb.common.Krb5Conf;

/**
 * Kerb KDC side configuration API.
 */
public class AdminServerConfig extends Krb5Conf {
    private static final String KDCDEFAULT = "kdcdefaults";

    public boolean enableDebug() {
        return getBoolean(AdminServerConfigKey.KRB_DEBUG, true, KDCDEFAULT);
    }

    public String getAdminServiceName() {
        return getString(AdminServerConfigKey.ADMIN_SERVICE_NAME, true, KDCDEFAULT);
    }

    public String getAdminHost() {
        return getString(AdminServerConfigKey.ADMIN_HOST, true, KDCDEFAULT);
    }

    public int getAdminPort() {
        Integer kdcPort = getInt(AdminServerConfigKey.ADMIN_PORT, true, KDCDEFAULT);
        if (kdcPort != null && kdcPort > 0) {
            return kdcPort.intValue();
        }
        return -1;
    }

    public int getAdminTcpPort() {
        Integer kdcTcpPort = getInt(AdminServerConfigKey.ADMIN_TCP_PORT, true, KDCDEFAULT);
        if (kdcTcpPort != null && kdcTcpPort > 0) {
            return kdcTcpPort.intValue();
        }
        return getAdminPort();
    }

    /**
     * Is to allow TCP for KDC
     * @return true to allow TCP, false otherwise
     */
    public Boolean allowTcp() {
        return getBoolean(AdminServerConfigKey.ADMIN_ALLOW_TCP, true, KDCDEFAULT)
                || getInt(AdminServerConfigKey.ADMIN_TCP_PORT, true, KDCDEFAULT) != null
            || getInt(AdminServerConfigKey.ADMIN_PORT, false, KDCDEFAULT) != null;
    }

    /**
     * Is to allow UDP for KDC
     * @return true to allow UDP, false otherwise
     */
    public Boolean allowUdp() {
        return getBoolean(AdminServerConfigKey.ADMIN_ALLOW_UDP, true, KDCDEFAULT)
                || getInt(AdminServerConfigKey.ADMIN_UDP_PORT, true, KDCDEFAULT) != null
            || getInt(AdminServerConfigKey.ADMIN_PORT, false, KDCDEFAULT) != null;
    }

    public int getAdminUdpPort() {
        Integer kdcUdpPort = getInt(AdminServerConfigKey.ADMIN_UDP_PORT, true, KDCDEFAULT);
        if (kdcUdpPort != null && kdcUdpPort > 0) {
            return kdcUdpPort.intValue();
        }
        return getAdminPort();
    }

    public String getAdminRealm() {
        return getString(AdminServerConfigKey.ADMIN_REALM, true, KDCDEFAULT);
    }

    public String getAdminDomain() {
        return getString(AdminServerConfigKey.ADMIN_DOMAIN, true, KDCDEFAULT);
    }
}
