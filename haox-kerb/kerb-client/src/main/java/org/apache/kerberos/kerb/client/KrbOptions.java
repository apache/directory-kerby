package org.apache.kerberos.kerb.client;

import java.util.HashMap;
import java.util.Map;

public class KrbOptions {

    private Map<KrbOption, KrbOption> options = new HashMap<KrbOption, KrbOption>(4);

    public void add(KrbOption option) {
        if (option != null) {
            options.put(option, option);
        }
    }

    public void add(KrbOption option, Object optionValue) {
        option.setValue(optionValue);
        add(option);
    }

    public boolean contains(KrbOption option) {
        return options.containsKey(option);
    }

    public KrbOption getOption(KrbOption option) {
        if (! options.containsKey(option)) {
            return null;
        }

        return options.get(option);
    }

    public Object getOptionValue(KrbOption option) {
        if (! contains(option)) {
            return null;
        }
        return options.get(option).getValue();
    }

    public String getStringOption(KrbOption option) {
        Object value = getOptionValue(option);
        if (value != null && value instanceof String) {
            return (String) value;
        }
        return null;
    }

    public boolean getBooleanOption(KrbOption option) {
        Object value = getOptionValue(option);
        if (value != null) {
            if (value instanceof String) {
                String strVal = (String) value;
                if (strVal.equalsIgnoreCase("true") ||
                        strVal.equalsIgnoreCase("yes") ||
                        strVal.equals("1")) {
                    return true;
                }
            } else if (value instanceof Boolean) {
                return (Boolean) value;
            }
        }
        return false;
    }

    public int getIntegerOption(KrbOption option) {
        Object value = getOptionValue(option);
        if (value != null) {
            if (value instanceof String) {
                String strVal = (String) value;
                return Integer.valueOf(strVal);
            } else if (value instanceof Integer) {
                return (Integer) value;
            }
        }
        return -1;
    }
}
