package org.haox.kerb.client;

import org.apache.haox.config.ConfigKey;

public enum KrbConfigKey implements ConfigKey {
    KRB_DEBUG(true),
    KDC_HOST("localhost"),
    KDC_PORT(8015),
    KDC_DOMAIN("example.com"),
    KDC_REALM("EXAMPLE.COM"),
    TGS_PRINCIPAL("krbtgt@EXAMPLE.COM"),
    PREAUTH_REQUIRED(true),
    ALLOWABLE_CLOCKSKEW(5 * 60),
    EMPTY_ADDRESSES_ALLOWED(true),
    PA_ENC_TIMESTAMP_REQUIRED(true),
    MAXIMUM_TICKET_LIFETIME(24 * 3600),
    MINIMUM_TICKET_LIFETIME(1 * 3600),
    MAXIMUM_RENEWABLE_LIFETIME(48 * 3600),
    FORWARDABLE_ALLOWED(true),
    POSTDATED_ALLOWED(true),
    PROXIABLE_ALLOWED(true),
    RENEWABLE_ALLOWED(true),
    VERIFY_BODY_CHECKSUM(true),
    ENCRYPTION_TYPES(new String[] { "aes128-cts-hmac-sha1-96", "des-cbc-md5" });

    private Object defaultValue;

    private KrbConfigKey() {
        this.defaultValue = null;
    }

    private KrbConfigKey(Object defaultValue) {
        this.defaultValue = defaultValue;
    }

    @Override
    public String getPropertyKey() {
        return name().toLowerCase();
    }

    @Override
    public Object getDefaultValue() {
        return this.defaultValue;
    }
}
