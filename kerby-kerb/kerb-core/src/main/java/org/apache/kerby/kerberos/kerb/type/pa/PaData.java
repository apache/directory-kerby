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
package org.apache.kerby.kerberos.kerb.type.pa;

import org.apache.kerby.kerberos.kerb.type.KrbSequenceOfType;

/**
 * The PaData Sequence as defined in RFC 4120, like in :
 * 
 * <pre>
 * ...
 * padata          [3] SEQUENCE OF PA-DATA
 * ...
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PaData extends KrbSequenceOfType<PaDataEntry> {
    /**
     * Find a PaData from its type
     * 
     * @param paType The {@link PaDataType}
     * @return An instance of {@link PaDataEntry}, or null if not found
     */
    public PaDataEntry findEntry(PaDataType paType) {
        for (PaDataEntry pae : getElements()) {
            if (pae.getPaDataType() == paType) {
                return pae;
            }
        }
        
        return null;
    }
}
