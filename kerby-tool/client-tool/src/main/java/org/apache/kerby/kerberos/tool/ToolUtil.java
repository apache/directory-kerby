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
package org.apache.kerby.kerberos.tool;

import org.apache.kerby.kerberos.kerb.client.KOption;
import org.apache.kerby.kerberos.kerb.client.KOptionType;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.KOptions;

import java.io.File;

/**
 * Tool utilities.
 */
public class ToolUtil {

    /**
     * Parse string value according to kopt type.
     * @param kopt
     * @param strValue
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
            if (! dir.exists()) {
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
        } else {
            throw new IllegalArgumentException("Not recognised option:" + strValue);
        }

        return true;
    }

    /**
     * Convert tool (like kinit) options to KrbOptions.
     * @param krbOptions
     * @return krb options
     */
    public static KOptions convertOptions(KOptions krbOptions) {
        KOptions results = new KOptions();

        for (KOption toolOpt : krbOptions.getOptions()) {
            KrbOption krbOpt = KrbOption.fromOptionName(toolOpt.getOptionName());
            krbOpt.setValue(toolOpt.getValue());
            results.add(krbOpt);
        }

        return results;
    }
}
