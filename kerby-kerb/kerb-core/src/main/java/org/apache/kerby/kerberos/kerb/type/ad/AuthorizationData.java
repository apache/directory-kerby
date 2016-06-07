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
package org.apache.kerby.kerberos.kerb.type.ad;

import org.apache.kerby.kerberos.kerb.type.KrbSequenceOfType;

/**
 * The AuthorizationData  as defined in RFC 4120 :
 * <pre>
 * AuthorizationData       ::= SEQUENCE OF SEQUENCE {
 *         ad-type         [0] Int32,
 *         ad-data         [1] OCTET STRING
 * }
 * </pre>
 * 
 * This class is just empty, as the content is already stored in a SequenceOf.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AuthorizationData extends KrbSequenceOfType<AuthorizationDataEntry> {

    public AuthorizationData clone() {
        AuthorizationData result = new AuthorizationData();

        for (AuthorizationDataEntry entry : super.getElements()) {
            result.add(entry.clone());
        }

        return result;
    }
}
