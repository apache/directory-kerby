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
package org.apache.kerby.asn1.parse;

import org.apache.kerby.asn1.Asn1Dumpable;
import org.apache.kerby.asn1.Asn1Dumper;

import java.util.ArrayList;
import java.util.List;

/**
 * ASN1 constructed types, mainly structured ones, but also some primitive ones.
 */
public class Asn1Container
    extends Asn1ParseResult implements Asn1Dumpable {

    private List<Asn1ParseResult> children = new ArrayList<>();

    public Asn1Container(Asn1Header header) {
        super(header);
    }

    public Asn1Container(Asn1ParseResult parseResult) {
        super(parseResult.header);
    }

    public List<Asn1ParseResult> getChildren() {
        return children;
    }

    public void addItem(Asn1ParseResult value) {
        children.add(value);
    }

    public void clear() {
        children.clear();
    }

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        dumper.indent(indents).append(toString()).newLine();

        for (Asn1ParseResult aObj : children) {
            dumper.dumpParseResult(indents + 4, aObj).newLine();
        }
    }

    @Override
    public String toString() {
        String typeStr;
        if (tag().isUniversal()) {
            typeStr = tag().universalTag().toStr();
        } else if (tag().isAppSpecific()) {
            typeStr = "application " + tagNo();
        } else {
            typeStr = "[" + tagNo() + "]";
        }
        return typeStr + " ["
            + "off=" + getOffset()
            + ", len=" + getHeaderLength() + "+" + getBodyLength()
            + (isDefinitiveLength() ? "" : "(undefined)")
            + "]";
    }
}
