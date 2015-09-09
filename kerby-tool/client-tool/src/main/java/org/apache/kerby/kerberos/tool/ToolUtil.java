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

import org.apache.kerby.KOption;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.client.KrbOption;

/**
 * Tool utilities.
 */
public class ToolUtil {

    /**
     * Convert tool (like kinit) options to KrbOptions.
     * @param krbOptions krb options
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
