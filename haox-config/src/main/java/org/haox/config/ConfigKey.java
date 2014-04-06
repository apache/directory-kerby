package org.haox.config;

public interface ConfigKey {
    public String toPropertyKey();
    public Object getDefaultValue();
}
