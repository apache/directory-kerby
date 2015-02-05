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
package org.apache.kerby.kerberos.kerb.common;

import org.apache.kerby.kerberos.kerb.spec.common.*;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class KrbErrorUtil {

    public static List<EncryptionType> getEtypes(KrbError error) throws IOException {
        MethodData methodData = new MethodData();
        methodData.decode(error.getEdata());

        for( PaDataEntry pd : methodData.getElements()) {
            if( pd.getPaDataType() == PaDataType.ETYPE_INFO2 ) {
                return getEtypes2(pd.getPaDataValue());
            }
            else if( pd.getPaDataType() == PaDataType.ETYPE_INFO ) {
                return getEtypes(pd.getPaDataValue());
            }
        }
        return Collections.emptyList();
    }

    private static List<EncryptionType> getEtypes(byte[] data) throws IOException {
        EtypeInfo info = new EtypeInfo();
        info.decode(data);
        List<EncryptionType> results = new ArrayList<EncryptionType>();
        for( EtypeInfoEntry entry : info.getElements() ) {
            results.add(entry.getEtype());
        }
        return results;
    }

    private static List<EncryptionType> getEtypes2(byte[] data) throws IOException {
        EtypeInfo2 info2 = new EtypeInfo2();
        info2.decode(data);
        List<EncryptionType> results = new ArrayList<EncryptionType>();
        for( EtypeInfo2Entry entry : info2.getElements() ) {
            results.add(entry.getEtype());
        }
        return results;
    }
}
