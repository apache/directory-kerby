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

import org.apache.kerby.asn1.UniversalTag;

public class Asn1NumericsString extends Asn1String {
    public Asn1NumericsString() {
        this(null);
    }

    public Asn1NumericsString(String value) {
        super(UniversalTag.NUMERIC_STRING, value);
        if (value != null && !isNumeric(value)) {
             throw new IllegalArgumentException("Invalid numeric string");
        }
    }

    public static boolean isNumeric(String  s) {
        for (int i = s.length() - 1; i >= 0; i--) {
            char c = s.charAt(i);
            if (!(c >= '0' && c <= '9' || c == ' ')) {
                return false;
            }
        }
        return true;
    }
}
