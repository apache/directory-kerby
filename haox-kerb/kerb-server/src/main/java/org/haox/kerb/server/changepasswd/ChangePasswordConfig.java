package org.haox.kerb.server.changepasswd;

import org.haox.config.ConfigKey;
import org.haox.kerb.server.common.KdcConfig;

public class ChangePasswordConfig extends KdcConfig
{
    public static enum ChangePasswordConfigKey implements ConfigKey {
        SERVICE_NAME("Haox_ChangePassword_Server"),
        SERVER_ADDRESS("127.0.0.1"),
        SERVER_PORT(8016),
        SERVICE_PRINCIPAL("kadmin/changepw@EXAMPLE.COM"),
        PASSWORD_LENGTH(6),
        TOKEN_SIZE(3);

        private Object defaultValue;

        private ChangePasswordConfigKey() {
            this.defaultValue = null;
        }

        private ChangePasswordConfigKey(Object defaultValue) {
            this.defaultValue = defaultValue;
        }

        @Override
        public String getPropertyKey() {
            return "change_password_" + name().toLowerCase();
        }

        @Override
        public Object getDefaultValue() {
            return this.defaultValue;
        }
    }

    public String getServiceName() {
        return conf.getString(ChangePasswordConfigKey.SERVICE_NAME);
    }

    public String getServerAddress() {
        return conf.getString(ChangePasswordConfigKey.SERVER_ADDRESS);
    }

    public int getServerPort() {
        return conf.getInt(ChangePasswordConfigKey.SERVER_PORT);
    }

    public String getServicePrincipal() {
        return conf.getString(ChangePasswordConfigKey.SERVICE_PRINCIPAL);
    }

    public int getPasswordLength() {
        return conf.getInt(ChangePasswordConfigKey.PASSWORD_LENGTH);
    }
}
