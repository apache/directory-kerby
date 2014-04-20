package org.haox.kerb.server.common;

import org.haox.config.Conf;

import java.util.List;

public class KdcConfig
{
    private Conf conf;

    public KdcConfig() {
        this.conf = new Conf();
    }

    public Conf getConf() {
        return this.conf;
    }

    public boolean enableDebug() {
        return conf.getBoolean(KdcConfigKey.KRB_DEBUG);
    }

    public String getKdcServiceName() {
        return conf.getString(KdcConfigKey.KDC_SERVICE_NAME);
    }

    public String getWorkDir() {
        return conf.getString(KdcConfigKey.WORK_DIR);
    }

    public String getKdcAddress() {
        return conf.getString(KdcConfigKey.KDC_ADDRESS);
    }

    public int getKdcPort() {
        return conf.getInt(KdcConfigKey.KDC_PORT);
    }

    public String getKdcRealm() {
        return conf.getString(KdcConfigKey.KDC_REALM);
    }

    public String getKdcDomain() {
        return conf.getString(KdcConfigKey.KDC_DOMAIN);
    }

    public String getKdcDn() {
        return conf.getString(KdcConfigKey.KDC_DN);
    }

    public String getTgsPrincipal() {
        return conf.getString(KdcConfigKey.TGS_PRINCIPAL);
    }

    public long getAllowableClockSkew() {
        return conf.getLong(KdcConfigKey.ALLOWABLE_CLOCKSKEW);
    }

    public boolean isEmptyAddressesAllowed() {
        return conf.getBoolean(KdcConfigKey.EMPTY_ADDRESSES_ALLOWED);
    }

    public boolean isForwardableAllowed() {
        return conf.getBoolean(KdcConfigKey.FORWARDABLE_ALLOWED);
    }

    public boolean isPostdatedAllowed() {
        return conf.getBoolean(KdcConfigKey.POSTDATED_ALLOWED);
    }

    public boolean isProxiableAllowed() {
        return conf.getBoolean(KdcConfigKey.PROXIABLE_ALLOWED);
    }

    public boolean isRenewableAllowed() {
        return conf.getBoolean(KdcConfigKey.RENEWABLE_ALLOWED);
    }

    public long getMaximumRenewableLifetime() {
        return conf.getLong(KdcConfigKey.MAXIMUM_RENEWABLE_LIFETIME);
    }

    public long getMaximumTicketLifetime() {
        return conf.getLong(KdcConfigKey.MAXIMUM_TICKET_LIFETIME);
    }

    public long getMinimumTicketLifetime() {
        return conf.getLong(KdcConfigKey.MINIMUM_TICKET_LIFETIME);
    }

    public List<String> getEncryptionTypes() {
        return conf.getList(KdcConfigKey.ENCRYPTION_TYPES);
    }

    public boolean isPaEncTimestampRequired() {
        return conf.getBoolean(KdcConfigKey.PA_ENC_TIMESTAMP_REQUIRED);
    }

    public boolean isBodyChecksumVerified() {
        return conf.getBoolean(KdcConfigKey.VERIFY_BODY_CHECKSUM);
    }
}
