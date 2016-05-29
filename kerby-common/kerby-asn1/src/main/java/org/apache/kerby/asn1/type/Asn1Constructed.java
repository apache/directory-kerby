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

import org.apache.kerby.asn1.Asn1Converter;
import org.apache.kerby.asn1.Asn1Dumpable;
import org.apache.kerby.asn1.Asn1Dumper;
import org.apache.kerby.asn1.Tag;
import org.apache.kerby.asn1.parse.Asn1Container;
import org.apache.kerby.asn1.parse.Asn1ParseResult;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * ASN1 constructed types, mainly structured ones, but also some primitive ones.
 */
public class Asn1Constructed
    extends AbstractAsn1Type<List<Asn1Type>> implements Asn1Dumpable {

    protected Asn1Container container;

    private boolean lazy = false;

    public Asn1Constructed(Tag tag) {
        super(tag);
        setValue(new ArrayList<Asn1Type>());
        usePrimitive(false);
    }


    public Asn1Container getContainer() {
        return container;
    }

    public void setLazy(boolean lazy) {
        this.lazy = lazy;
    }

    public boolean isLazy() {
        return lazy;
    }

    public void addItem(Asn1Type value) {
        resetBodyLength();
        getValue().add(value);
        if (value instanceof Asn1Encodeable) {
            ((Asn1Encodeable) value).outerEncodeable = this;
        }
    }

    public void clear() {
        resetBodyLength();
        getValue().clear();
    }

    @Override
    protected int encodingBodyLength() throws IOException {
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
    protected void encodeBody(ByteBuffer buffer) throws IOException {
        List<Asn1Type> valueItems = getValue();
        for (Asn1Type item : valueItems) {
            if (item != null) {
                item.encode(buffer);
            }
        }
    }

    @Override
    protected void decodeBody(Asn1ParseResult parseResult) throws IOException {
        Asn1Container container = (Asn1Container) parseResult;
        this.container = container;
        useDefinitiveLength(parseResult.isDefinitiveLength());

        if (!isLazy()) {
            decodeElements();
        }
    }

    protected void decodeElements() throws IOException {
        for (Asn1ParseResult parsingItem : getContainer().getChildren()) {
            if (parsingItem.isEOC()) {
                continue;
            }

            Asn1Type tmpValue = Asn1Converter.convert(parsingItem, lazy);
            addItem(tmpValue);
        }
    }

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        String typeStr = tag().typeStr() + " ["
            + "tag=" + tag()
            + ", len=" + getHeaderLength() + "+" + getBodyLength()
            + "] ";
        dumper.indent(indents).append(typeStr).newLine();

        List<Asn1Type> items = getValue();
        int i = 0;
        for (Asn1Type aObj : items) {
            dumper.dumpType(indents + 4, aObj);
            if (i++ != items.size() - 1) {
                dumper.newLine();
            }
        }
    }
}