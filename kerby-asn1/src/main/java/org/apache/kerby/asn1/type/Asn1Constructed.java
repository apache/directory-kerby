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
package org.apache.kerby.asn1.type;

import org.apache.kerby.asn1.Asn1Dumpable;
import org.apache.kerby.asn1.Asn1Dumper;
import org.apache.kerby.asn1.Asn1Header;
import org.apache.kerby.asn1.Tag;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * ASN1 constructed types, mainly structured ones, but also some primitive ones.
 */
public class Asn1Constructed
    extends AbstractAsn1Type<List<Asn1Type>> implements Asn1Dumpable {

    private boolean lazy = false;

    public Asn1Constructed(Tag tag) {
        super(tag);
        setValue(new ArrayList<Asn1Type>());
        usePrimitive(false);
    }

    public void setLazy(boolean lazy) {
        this.lazy = lazy;
    }

    public boolean isLazy() {
        return lazy;
    }

    public void addItem(Asn1Type value) {
        getValue().add(value);
    }

    public void clear() {
        getValue().clear();
    }

    @Override
    protected int encodingBodyLength() {
        List<Asn1Type> valueItems = getValue();
        int allLen = 0;
        for (Asn1Type item : valueItems) {
            if (item != null) {
                allLen += item.encodingLength();
            }
        }
        return allLen;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        List<Asn1Type> valueItems = getValue();
        for (Asn1Type item : valueItems) {
            if (item != null) {
                item.encode(buffer);
            }
        }
    }

    @Override
    protected void decodeBody(Asn1Header header) throws IOException {
        Asn1ParsingContainer container = new Asn1ParsingContainer(tag());
        container.decode(header);

        for (Asn1ParsingResult result : container.getParsingResults()) {
            Asn1Item item = new Asn1Item(result);
            if (item.isSimple() && !isLazy()) {
                item.decodeValueAsSimple();
                addItem(item.getValue());
            } else {
                addItem(item);
            }
        }
    }

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        dumper.indent(indents).append(toString()).newLine();

        for (Asn1Type aObj : getValue()) {
            dumper.dumpType(indents + 4, aObj).newLine();
        }
    }
}