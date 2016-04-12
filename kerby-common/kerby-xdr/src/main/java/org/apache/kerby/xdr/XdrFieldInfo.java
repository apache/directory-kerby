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
package org.apache.kerby.xdr;

/**
 * Representing a field in a XDR struct.
 */
public class XdrFieldInfo {
    private int index;
    //private Class<? extends XdrType> type;
    private XdrDataType dataType;
    private Object value;

    /**
     * Constructor.
     * @param index
     * @param dataType
     *
     */
    public XdrFieldInfo(int index, XdrDataType dataType, Object value) {
        //Class<? extends XdrType> type
        this.index = index;
        //this.type = type;
        this.dataType = dataType;
        this.value = value;
    }

    public int getIndex() {
        return index;
    }

    //public Class<? extends XdrType> getTypeClass() {
        //return type;
    //}

    public XdrDataType getDataType() {
        return dataType;
    }

    public Object getValue() {
        return value;
    }
}
