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

import java.io.IOException;
import java.util.List;

import org.apache.kerby.asn1.Asn1Dumper;
import org.apache.kerby.asn1.type.Asn1Utf8String;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceOfType;

/**
 * Contributed to the Apache Kerby Project by: Prodentity - Corrales, NM
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache DirectoryProject</a>
 */
public class ADAuthenticationIndicator extends AuthorizationDataEntry {

    private AuthIndicator myAuthIndicator;

    private class AuthIndicator extends KrbSequenceOfType<Asn1Utf8String> {
    }

    public ADAuthenticationIndicator() {
        super(AuthorizationType.AD_AUTHENTICAION_INDICATOR);
        myAuthIndicator = new AuthIndicator();
        myAuthIndicator.outerEncodeable = this;
    }

    public ADAuthenticationIndicator(byte[] encoded) throws IOException {
        this();
        myAuthIndicator.decode(encoded);
    }

    public List<Asn1Utf8String> getAuthIndicators() {
        return myAuthIndicator.getElements();
    }

    public void add(Asn1Utf8String indicator) {
        myAuthIndicator.add(indicator);
        resetBodyLength();
    }

    public void clear() {
        myAuthIndicator.clear();
        resetBodyLength();
    }

    @Override
    protected int encodingBodyLength() throws IOException {
        if (bodyLength == -1) {
            setAuthzData(myAuthIndicator.encode());
            bodyLength = super.encodingBodyLength();
        }
        return bodyLength;
    };

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        super.dumpWith(dumper, indents);
        dumper.newLine();
        myAuthIndicator.dumpWith(dumper, indents + 8);
    }

}
