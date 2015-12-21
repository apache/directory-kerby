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
import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.Tag;
import org.apache.kerby.asn1.parse.Asn1ParseResult;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * For tagging a collection type with tagNo, either application specific or
 * context specific class
 */
public abstract class Asn1TaggingCollection
    extends AbstractAsn1Type<Asn1CollectionType> implements Asn1Dumpable {

    private Asn1Tagging<Asn1CollectionType> tagging;
    private Asn1CollectionType tagged;

    public Asn1TaggingCollection(int taggingTagNo, Asn1FieldInfo[] tags,
                                 boolean isAppSpecific, boolean isImplicit) {
        super(makeTag(isAppSpecific, taggingTagNo));
        this.tagged = createTaggedCollection(tags);
        setValue(tagged);
        this.tagging = new Asn1Tagging<>(taggingTagNo,
            tagged, isAppSpecific, isImplicit);
    }

    private static Tag makeTag(boolean isAppSpecific, int tagNo) {
        return isAppSpecific ? Tag.newAppTag(tagNo) : Tag.newCtxTag(tagNo);
    }

    protected abstract Asn1CollectionType createTaggedCollection(Asn1FieldInfo[] tags);

    @Override
    public Tag tag() {
        return tagging.tag();
    }

    @Override
    public int tagNo() {
        return tagging.tagNo();
    }

    @Override
    public void usePrimitive(boolean isPrimitive) {
        tagging.usePrimitive(isPrimitive);
    }

    @Override
    public boolean isPrimitive() {
        return tagging.isPrimitive();
    }

    @Override
    public void useDefinitiveLength(boolean isDefinitiveLength) {
        tagging.useDefinitiveLength(isDefinitiveLength);
    }

    @Override
    public boolean isDefinitiveLength() {
        return tagging.isDefinitiveLength();
    }

    @Override
    public void useImplicit(boolean isImplicit) {
        tagging.useImplicit(isImplicit);
    }

    @Override
    public boolean isImplicit() {
        return tagging.isImplicit();
    }

    @Override
    public void useDER() {
        tagging.useDER();
    }

    @Override
    public boolean isDER() {
        return tagging.isDER();
    }

    @Override
    public void useBER() {
        tagging.useBER();
    }

    @Override
    public boolean isBER() {
        return tagging.isBER();
    }

    @Override
    public void useCER() {
        tagging.useCER();
    }

    @Override
    public boolean isCER() {
        return tagging.isCER();
    }


    @Override
    protected int encodingBodyLength() throws IOException {
        return tagging.encodingBodyLength();
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) throws IOException {
        tagging.encodeBody(buffer);
    }

    @Override
    public void decode(ByteBuffer content) throws IOException {
        tagging.decode(content);
    }

    @Override
    protected void decodeBody(Asn1ParseResult parseResult) throws IOException {
        tagging.decodeBody(parseResult);
    }

    protected <T extends Asn1Type> T getFieldAs(EnumType index, Class<T> t) {
        return tagged.getFieldAs(index, t);
    }

    protected void setFieldAs(EnumType index, Asn1Type value) {
        tagged.setFieldAs(index, value);
    }

    protected String getFieldAsString(EnumType index) {
        return tagged.getFieldAsString(index);
    }

    protected byte[] getFieldAsOctets(EnumType index) {
        return tagged.getFieldAsOctets(index);
    }

    protected void setFieldAsOctets(EnumType index, byte[] bytes) {
        tagged.setFieldAsOctets(index, bytes);
    }

    protected Integer getFieldAsInteger(EnumType index) {
        return tagged.getFieldAsInteger(index);
    }

    protected void setFieldAsInt(EnumType index, int value) {
        tagged.setFieldAsInt(index, value);
    }

    protected byte[] getFieldAsOctetBytes(EnumType index) {
        return tagged.getFieldAsOctets(index);
    }

    protected void setFieldAsOctetBytes(EnumType index, byte[] value) {
        tagged.setFieldAsOctets(index, value);
    }

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        Asn1Type taggedValue = getValue();
        dumper.indent(indents).appendType(getClass());
        dumper.append(simpleInfo()).newLine();
        dumper.dumpType(indents, taggedValue);
    }
}
