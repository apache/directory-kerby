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
import org.apache.kerby.asn1.Tag;
import org.apache.kerby.asn1.parse.Asn1Container;
import org.apache.kerby.asn1.parse.Asn1ParseResult;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.nio.ByteBuffer;

/**
 * For tagging any Asn1Type with a tagNo
 */
public class Asn1Tagging<T extends Asn1Type>
    extends AbstractAsn1Type<T> implements Asn1Dumpable {

    public Asn1Tagging(int tagNo, T value,
                       boolean isAppSpecific, boolean isImplicit) {
        super(makeTag(isAppSpecific, tagNo), value);
        if (value == null) {
            initValue();
        }
        useImplicit(isImplicit);
    }

    private static Tag makeTag(boolean isAppSpecific, int tagNo) {
        return isAppSpecific ? Tag.newAppTag(tagNo) : Tag.newCtxTag(tagNo);
    }

    @Override
    public void useImplicit(boolean isImplicit) {
        super.useImplicit(isImplicit);

        if (!isImplicit) {
            //In effect, explicitly tagged types are structured types consisting
            // of one component, the underlying type.
            usePrimitive(false);
        } else {
            usePrimitive(getValue().isPrimitive());
        }
    }

    @Override
    protected int encodingBodyLength() throws IOException {
        Asn1Encodeable value = (Asn1Encodeable) getValue();
        if (isImplicit()) {
            return value.encodingBodyLength();
        } else {
            return value.encodingLength();
        }
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) throws IOException {
        Asn1Encodeable value = (Asn1Encodeable) getValue();
        if (isImplicit()) {
            value.encodeBody(buffer);
        } else {
            value.encode(buffer);
        }
    }

    @Override
    protected void decodeBody(Asn1ParseResult parseResult) throws IOException {
        Asn1Encodeable value = (Asn1Encodeable) getValue();
        if (isImplicit()) {
            value.decodeBody(parseResult);
        } else {
            Asn1Container container = (Asn1Container) parseResult;
            Asn1ParseResult body = container.getChildren().get(0);
            value.decode(body);
        }
    }

    private void initValue() {
        Class<? extends Asn1Type> valueType = (Class<T>) ((ParameterizedType)
                getClass().getGenericSuperclass()).getActualTypeArguments()[0];
        AbstractAsn1Type<?> value;
        try {
            value = (AbstractAsn1Type<?>) valueType.newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create tagged value", e);
        }
        setValue((T) value);
    }

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        Asn1Type taggedValue = getValue();
        dumper.indent(indents).appendType(getClass());
        dumper.append(simpleInfo()).newLine();
        dumper.dumpType(indents, taggedValue);
    }
}
