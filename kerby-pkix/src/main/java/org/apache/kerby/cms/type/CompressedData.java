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
package org.apache.kerby.cms.type;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.x509.type.AlgorithmIdentifier;

/** 
 * Ref. RFC 3274
 * 
 * <pre>
 * CompressedData ::= SEQUENCE {
 *     version CMSVersion,
 *     compressionAlgorithm CompressionAlgorithmIdentifier,
 *     encapContentInfo EncapsulatedContentInfo
 * }
 * </pre>
 */
public class CompressedData extends Asn1SequenceType {
    protected enum CompressedDataField implements EnumType {
        VERSION,
        COMPRESSION_ALGORITHM,
        ENCAP_CONTENT_INFO;

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
            new Asn1FieldInfo(CompressedDataField.VERSION, CmsVersion.class),
            new Asn1FieldInfo(CompressedDataField.COMPRESSION_ALGORITHM, AlgorithmIdentifier.class),
            new Asn1FieldInfo(CompressedDataField.ENCAP_CONTENT_INFO, EncapsulatedContentInfo.class)
    };

    public CompressedData() {
        super(fieldInfos);
    }

    public CmsVersion getVersion() {
        return getFieldAs(CompressedDataField.VERSION, CmsVersion.class);
    }

    public void setVersion(CmsVersion version) {
        setFieldAs(CompressedDataField.VERSION, version);
    }

    public AlgorithmIdentifier getCompressionAlgorithm() {
        return getFieldAs(CompressedDataField.COMPRESSION_ALGORITHM, AlgorithmIdentifier.class);
    }

    public void setCompressionAlgorithm(AlgorithmIdentifier compressionAlgorithm) {
        setFieldAs(CompressedDataField.COMPRESSION_ALGORITHM, compressionAlgorithm);
    }

    public EncapsulatedContentInfo getEncapContentInfo() {
        return getFieldAs(CompressedDataField.ENCAP_CONTENT_INFO, EncapsulatedContentInfo.class);
    }

    public void setEncapContentInfo(EncapsulatedContentInfo encapContentInfo) {
        setFieldAs(CompressedDataField.ENCAP_CONTENT_INFO, encapContentInfo);
    }

}
