package org.apache.kerby.kerberos.kerb.client;

import org.apache.kerby.kerberos.kerb.server.KdcSetting;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.util.IOUtil;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

/**
 * Generate krb5 file using given kdc server settings.
 */
public class Krb5Conf {
    private static final String KRB5_CONF = "java.security.krb5.conf";
    private static final String KRB5_CONF_FILE = "krb5.conf";
    private SimpleKdcServer kdcServer;

    public Krb5Conf(SimpleKdcServer kdcServer) {
        this.kdcServer = kdcServer;
    }

    public void initKrb5conf() throws IOException {
        File confFile = generateConfFile();
        System.setProperty(KRB5_CONF, confFile.getAbsolutePath());
    }

    // Read in krb5.conf and substitute in the correct port
    private File generateConfFile() throws IOException {
        KdcSetting setting = kdcServer.getKdcSetting();

        String resourcePath = setting.allowUdp() ? "/krb5_udp.conf" : "/krb5.conf";
        InputStream templateResource = getClass().getResourceAsStream(resourcePath);
        String templateContent = IOUtil.readInput(templateResource);

        String content = templateContent;

        content = content.replaceAll("_REALM_", "" + setting.getKdcRealm());

        int kdcPort = setting.allowUdp() ? setting.getKdcUdpPort() :
                setting.getKdcTcpPort();
        content = content.replaceAll("_PORT_",
                String.valueOf(kdcPort));

        int udpLimit = setting.allowUdp() ? 4096 : 1;
        content = content.replaceAll("_UDP_LIMIT_", String.valueOf(udpLimit));

        File confFile = new File(kdcServer.getWorkDir(), KRB5_CONF_FILE);
        IOUtil.writeFile(content, confFile);

        return confFile;
    }
}
