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
import org.apache.kerby.kerberos.kerb.type.KrbSequenceOfType;

/**
 * Contributed to the Apache Kerby Project by: Prodentity - Corrales, NM
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache DirectoryProject</a>
 */
public class ADAndOr extends AuthorizationDataEntry {

    private KrbSequenceOfType<AndOr> myAndOr;

    public ADAndOr() {
        super(AuthorizationType.AD_AND_OR);
        myAndOr = new KrbSequenceOfType<AndOr>();
        myAndOr.outerEncodeable = this;
    }

    public ADAndOr(byte[] encoded) throws IOException {
        this();
        myAndOr.decode(encoded);
    }

    public ADAndOr(List<AndOr> elements) {
        this();
        for (AndOr element : elements) {
            myAndOr.add(element);
        }
    }

    public List<AndOr> getAndOrs() throws IOException {
        return myAndOr.getElements();
    }

    public void add(AndOr element) {
        myAndOr.add(element);
    }

    @Override
    protected int encodingBodyLength() throws IOException {
        if (bodyLength == -1) {
            setAuthzData(myAndOr.encode());
            bodyLength = super.encodingBodyLength();
        }
        return bodyLength;
    };

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        super.dumpWith(dumper, indents);
        dumper.newLine();
        myAndOr.dumpWith(dumper, indents + 8);
    }
}
