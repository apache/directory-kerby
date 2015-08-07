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
package org.apache.kerby.kerberos.tool.kadmin;

import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.util.IOUtil;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

/**
 * Generate krb5 file using given kdc server settings.
 */
public class Krb5Conf {
    public static final String KRB5_CONF = "java.security.krb5.conf";
    private static final String KRB5_CONF_FILE = "krb5.conf";
    private File confDir;
    private KdcConfig kdcConfig;

    public Krb5Conf(File confDir, KdcConfig kdcConfig) {
        this.confDir = confDir;
        this.kdcConfig = kdcConfig;
    }

    public void initKrb5conf() throws IOException {
        File confFile = generateConfFile();
        System.setProperty(KRB5_CONF, confFile.getAbsolutePath());
    }

    // Read in krb5.conf and substitute in the correct port
    private File generateConfFile() throws IOException {

        String resourcePath = kdcConfig.allowUdp() ? "/krb5_udp.conf" : "/krb5.conf";
        InputStream templateResource = getClass().getResourceAsStream(resourcePath);

        String templateContent = IOUtil.readInput(templateResource);

        String content = templateContent;

        content = content.replaceAll("_REALM_", "" + kdcConfig.getKdcRealm());

        int kdcPort = kdcConfig.allowUdp() ? kdcConfig.getKdcUdpPort()
                : kdcConfig.getKdcTcpPort();
        content = content.replaceAll("_KDC_PORT_",
                String.valueOf(kdcPort));

        if (kdcConfig.allowTcp()) {
            content = content.replaceAll("#_KDC_TCP_PORT_", "kdc_tcp_port = " + kdcConfig.getKdcTcpPort());
        }
        if (kdcConfig.allowUdp()) {
            content = content.replaceAll("#_KDC_UDP_PORT_", "kdc_udp_port = " + kdcConfig.getKdcUdpPort());
        }

        int udpLimit = kdcConfig.allowUdp() ? 4096 : 1;
        content = content.replaceAll("_UDP_LIMIT_", String.valueOf(udpLimit));

        File confFile = new File(confDir, KRB5_CONF_FILE);
        if (confFile.exists()) {
            confFile.delete();
        }
        IOUtil.writeFile(content, confFile);

        return confFile;
    }
}
