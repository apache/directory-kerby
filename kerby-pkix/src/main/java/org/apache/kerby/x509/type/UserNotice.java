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
package org.apache.kerby.x509.type;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 *
 * <pre>
 * UserNotice ::= SEQUENCE {
 *      noticeRef        NoticeReference OPTIONAL,
 *      explicitText     DisplayText OPTIONAL}
 *
 * </pre>
 *
 */
public class UserNotice extends Asn1SequenceType {
    protected enum UserNoticeField implements EnumType {
        NOTICE_REF,
        EXPLICIT_TEXT;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(UserNoticeField.NOTICE_REF, NoticeReference.class),
        new Asn1FieldInfo(UserNoticeField.EXPLICIT_TEXT, DisplayText.class)
    };

    public UserNotice() {
        super(fieldInfos);
    }

    public NoticeReference getNoticeRef() {
        return getFieldAs(UserNoticeField.NOTICE_REF, NoticeReference.class);
    }

    public void setNoticeRef(NoticeReference noticeRef) {
        setFieldAs(UserNoticeField.NOTICE_REF, noticeRef);
    }
    
    public DisplayText getExplicitText() {
        return getFieldAs(UserNoticeField.EXPLICIT_TEXT, DisplayText.class);
    }

    public void setExplicitText(DisplayText explicitText) {
        setFieldAs(UserNoticeField.EXPLICIT_TEXT, explicitText);
    }
}
