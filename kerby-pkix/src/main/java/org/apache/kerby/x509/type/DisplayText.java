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

import org.apache.kerby.asn1.type.Asn1BmpString;
import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1IA5String;
import org.apache.kerby.asn1.type.Asn1Utf8String;
import org.apache.kerby.asn1.type.Asn1VisibleString;

/**
 * <pre>
 * DisplayText ::= CHOICE {
 *      ia5String        IA5String      (SIZE (1..200)),
 *      visibleString    VisibleString  (SIZE (1..200)),
 *      bmpString        BMPString      (SIZE (1..200)),
 *      utf8String       UTF8String     (SIZE (1..200))
 *  }
 * </pre>
 */
public class DisplayText extends Asn1Choice {
   private static final int IA5_STRING = 0;
   private static final int VISIBLE_STRING = 1;
   private static final int BMP_STRING = 2;
   private static final int UTF8_STRING = 3;

   static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[]{
           new Asn1FieldInfo(IA5_STRING, Asn1IA5String.class),
           new Asn1FieldInfo(VISIBLE_STRING, Asn1VisibleString.class),
           new Asn1FieldInfo(BMP_STRING, Asn1BmpString.class),
           new Asn1FieldInfo(UTF8_STRING, Asn1BmpString.class)
   };

   public DisplayText() {
      super(fieldInfos);
   }

   public Asn1IA5String getIA5String() {
      return getFieldAs(IA5_STRING, Asn1IA5String.class);
   }

   public void setIA5String(Asn1IA5String ia5String) {
      setFieldAs(IA5_STRING, ia5String);
   }

   public Asn1VisibleString getVisibleString() {
      return getFieldAs(VISIBLE_STRING, Asn1VisibleString.class);
   }

   public void setVisibleString(Asn1VisibleString visibleString) {
      setFieldAs(VISIBLE_STRING, visibleString);
   }

   public Asn1BmpString getBmpString() {
      return getFieldAs(BMP_STRING, Asn1BmpString.class);
   }

   public void setBmpString(Asn1BmpString bmpString) {
      setFieldAs(BMP_STRING, bmpString);
   }

   public Asn1Utf8String getUtf8String() {
      return getFieldAs(UTF8_STRING, Asn1Utf8String.class);
   }

   public void setUtf8String(Asn1Utf8String utf8String) {
      setFieldAs(UTF8_STRING, utf8String);
   }
}
