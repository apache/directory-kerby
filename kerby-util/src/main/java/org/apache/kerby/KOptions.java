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
package org.apache.kerby;

import java.io.File;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A KOption container.
 */
public class KOptions {

    private final Map<KOption, KOption> options =
            new HashMap<KOption, KOption>();

    /**
     * Parse string value according to kopt type.
     * @param kopt The koption
     * @param strValue The string value
     * @return true when successful, false otherwise
     */
    public static boolean parseSetValue(KOption kopt, String strValue) {
        KOptionType kt = kopt.getType();
        if (kt == KOptionType.NOV) {
            return true; // no need of a value
        }
        if (strValue == null || strValue.isEmpty()) {
            return false;
        }

        if (kt == KOptionType.FILE) {
            // May check file sanity
            kopt.setValue(new File(strValue));
        } else if (kt == KOptionType.DIR) {
            File dir = new File(strValue);
            if (!dir.exists()) {
                throw new IllegalArgumentException("Invalid dir:" + strValue);
            }
            kopt.setValue(dir);
        } else if (kt == KOptionType.INT) {
            try {
                Integer num = Integer.valueOf(strValue);
                kopt.setValue(num);
            } catch (NumberFormatException nfe) {
                throw new IllegalArgumentException("Invalid integer:" + strValue);
            }
        } else if (kt == KOptionType.STR) {
            kopt.setValue(strValue);
        } else if (kt == KOptionType.DATE) {
            DateFormat df = new SimpleDateFormat("dd/MM/yy:HH:mm:ss");
            Date date = null;
            try {
                date = df.parse(strValue);
                kopt.setValue(date);
            } catch (ParseException e) {
                throw new IllegalArgumentException("Fail to parse the date: " + strValue);
            }
        } else if (kt == KOptionType.BOOL) {
            kopt.setValue(Boolean.valueOf(strValue));
        } else {
            throw new IllegalArgumentException("Not recognised option:" + strValue);
        }
        return true;
    }

    public void add(KOption option) {
        if (option != null) {
            options.put(option, option);
        }
    }

    public void add(KOption option, Object optionValue) {
        if (option != null) {
            option.setValue(optionValue);
            add(option);
        }
    }

    public boolean contains(KOption option) {
        return options.containsKey(option);
    }

    public List<KOption> getOptions() {
        return new ArrayList<>(options.keySet());
    }

    public KOption getOption(KOption option) {
        if (!options.containsKey(option)) {
            return null;
        }

        return options.get(option);
    }

    public Object getOptionValue(KOption option) {
        if (!contains(option)) {
            return null;
        }
        return options.get(option).getValue();
    }

    public String getStringOption(KOption option) {
        Object value = getOptionValue(option);
        if (value instanceof String) {
            return (String) value;
        }
        return null;
    }

    public boolean getBooleanOption(KOption option, Boolean defaultValue) {
        Object value = getOptionValue(option);
        if (value instanceof String) {
            String strVal = (String) value;
            if (strVal.equalsIgnoreCase("true")
                    || strVal.equalsIgnoreCase("yes")
                    || strVal.equals("1")) {
                return true;
            } else if (strVal.equalsIgnoreCase("false")
                    || strVal.equalsIgnoreCase("no")
                    || strVal.equals("0")) {
                return false;
            }
        } else if (value instanceof Boolean) {
            return (Boolean) value;
        }

        return defaultValue;
    }

    public int getIntegerOption(KOption option) {
        Object value = getOptionValue(option);
        if (value instanceof String) {
            String strVal = (String) value;
            return Integer.parseInt(strVal);
        } else if (value instanceof Integer) {
            return ((Integer) value).intValue();
        }
        return -1;
    }

    public File getFileOption(KOption option) {
        Object value = getOptionValue(option);
        if (value instanceof File) {
            return (File) value;
        }
        return null;
    }

    public File getDirOption(KOption option) {
        Object value = getOptionValue(option);
        if (value instanceof File) {
            return (File) value;
        }
        return null;
    }

    public Date getDateOption(KOption option) {
        Object value = getOptionValue(option);
        if (value instanceof Date) {
            return (Date) value;
        }
        return null;
    }
}
