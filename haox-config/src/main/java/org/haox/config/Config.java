package org.haox.config;

import java.util.List;
import java.util.Set;

public interface Config {
    public String getResource();
    public Set<String> getNames();

    public String getString(String name);
    public String getString(String name, String defaultValue);
    public String getTrimmed(String name);
    public Boolean getBoolean(String name);
    public Boolean getBoolean(String name, boolean defaultValue);
    public Integer getInt(String name);
    public Integer getInt(String name, int defaultValue);
    public Long getLong(String name);
    public Long getLong(String name, long defaultValue);
    public Float getFloat(String name);
    public Float getFloat(String name, float defaultValue);
    public List<String> getList(String name);
    public Config getConfig(String name);

    Class<?> getClass(String name, Class<?> defaultValue) throws ClassNotFoundException;
    <T> T getInstance(String name) throws ClassNotFoundException;
    <T> T getInstance(String name, Class<T> xface) throws ClassNotFoundException;
}
