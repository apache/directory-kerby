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

import org.apache.kerby.asn1.TaggingOption;

public class Asn1FieldInfo {
    private int index;
    private int tagNo;
    private boolean isImplicit;
    private Class<? extends Asn1Type> type;

    public Asn1FieldInfo(int index, int tagNo, Class<? extends Asn1Type> type) {
        this(index, tagNo, type, false);
    }

    public Asn1FieldInfo(int index, Class<? extends Asn1Type> type) {
        this(index, index, type, false);
    }

    public Asn1FieldInfo(int index, Class<? extends Asn1Type> type, boolean isImplicit) {
        this(index, index, type, isImplicit);
    }

    public Asn1FieldInfo(int index, int tagNo, Class<? extends Asn1Type> type, boolean isImplicit) {
        this.index = index;
        this.tagNo = tagNo;
        this.type = type;
        this.isImplicit = isImplicit;
    }

    public boolean isTagged() {
        return tagNo != -1;
    }

    public TaggingOption getTaggingOption() {
        if (isImplicit) {
            return TaggingOption.newImplicitContextSpecific(tagNo);
        } else {
            return TaggingOption.newExplicitContextSpecific(tagNo);
        }
    }

    public int getTagNo() {
        return tagNo;
    }

    public int getIndex() {
        return index;
    }

    public boolean isImplicit() {
        return isImplicit;
    }

    public Class<? extends Asn1Type> getType() {
        return type;
    }
}
