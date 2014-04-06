package org.haox.kerb.server.changepasswd;

import org.haox.config.ConfigKey;
import org.haox.kerb.server.common.KdcConfig;
import org.haox.kerb.server.common.KdcConfigKey;

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
        public String toPropertyKey() {
            return "change_password_" + name().toLowerCase();
        }

        @Override
        public Object getDefaultValue() {
            return this.defaultValue;
        }
    }

    public String getServiceName() {
        return config.getString(ChangePasswordConfigKey.SERVICE_NAME);
    }

    public String getServerAddress() {
        return config.getString(ChangePasswordConfigKey.SERVER_ADDRESS);
    }

    public int getServerPort() {
        return config.getInt(ChangePasswordConfigKey.SERVER_PORT);
    }

    public String getServicePrincipal() {
        return config.getString(ChangePasswordConfigKey.SERVICE_PRINCIPAL);
    }

    public int getPasswordLength() {
        return config.getInt(ChangePasswordConfigKey.PASSWORD_LENGTH);
    }
}
