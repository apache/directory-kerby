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
package org.apache.kerby.kerberos.kerb.preauth.pkinit;

import org.apache.kerby.kerberos.kerb.preauth.PreauthPluginMeta;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;

public class PkinitPreauthMeta implements PreauthPluginMeta {

    private static String NAME = "PKINIT";
    private static int VERSION = 1;
    private static PaDataType[] PA_TYPES = new PaDataType[] {
            PaDataType.PK_AS_REQ,
            PaDataType.PK_AS_REP,
    };

    @Override
    public String getName() {
        return NAME;
    }

    public int getVersion() {
        return VERSION;
    }

    public PaDataType[] getPaTypes() {
        return PA_TYPES;
    }
}
