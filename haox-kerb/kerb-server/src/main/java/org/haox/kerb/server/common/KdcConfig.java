package org.haox.kerb.server.common;

import org.haox.config.Conf;
import org.haox.config.Config;

import java.util.List;

public class KdcConfig
{
    protected Conf conf;
    protected Config config;

    public KdcConfig() {
        this.conf = new Conf();
        this.config = this.conf.getConfig();
    }

    public Conf getConf() {
        return this.conf;
    }

    public Config getConfig() {
        return conf.getConfig();
    }

    public String getKdcServiceName() {
        return config.getString(KdcConfigKey.KDC_SERVICE_NAME);
    }

    public String getKdcAddress() {
        return config.getString(KdcConfigKey.KDC_ADDRESS);
    }

    public int getKdcPort() {
        return config.getInt(KdcConfigKey.KDC_PORT);
    }

    public long getAllowableClockSkew() {
        return config.getLong(KdcConfigKey.ALLOWABLE_CLOCKSKEW);
    }

    public boolean isEmptyAddressesAllowed() {
        return config.getBoolean(KdcConfigKey.EMPTY_ADDRESSES_ALLOWED);
    }

    public boolean isForwardableAllowed() {
        return config.getBoolean(KdcConfigKey.FORWARDABLE_ALLOWED);
    }

    public boolean isPostdatedAllowed() {
        return config.getBoolean(KdcConfigKey.POSTDATED_ALLOWED);
    }

    public boolean isProxiableAllowed() {
        return config.getBoolean(KdcConfigKey.PROXIABLE_ALLOWED);
    }

    public boolean isRenewableAllowed() {
        return config.getBoolean(KdcConfigKey.RENEWABLE_ALLOWED);
    }

    public long getMaximumRenewableLifetime() {
        return config.getLong(KdcConfigKey.MAXIMUM_RENEWABLE_LIFETIME);
    }

    public long getMaximumTicketLifetime() {
        return config.getLong(KdcConfigKey.MAXIMUM_TICKET_LIFETIME);
    }

    public long getMinimumTicketLifetime() {
        return config.getLong(KdcConfigKey.MINIMUM_TICKET_LIFETIME);
    }

    public String getKdcRealm() {
        return config.getString(KdcConfigKey.KDC_REALM);
    }

    public String getTgsPrincipal() {
        return config.getString(KdcConfigKey.TGS_PRINCIPAL);
    }

    public List<String> getEncryptionTypes() {
        return config.getList(KdcConfigKey.ENCRYPTION_TYPES);
    }

    public boolean isPaEncTimestampRequired() {
        return config.getBoolean(KdcConfigKey.PA_ENC_TIMESTAMP_REQUIRED);
    }

    public boolean isBodyChecksumVerified() {
        return config.getBoolean(KdcConfigKey.VERIFY_BODY_CHECKSUM);
    }
}
