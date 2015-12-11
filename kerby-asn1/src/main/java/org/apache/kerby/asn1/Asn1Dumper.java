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
package org.apache.kerby.asn1;

import org.apache.kerby.asn1.parse.Asn1Item;
import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.type.Asn1Any;
import org.apache.kerby.asn1.type.Asn1Application;
import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.asn1.type.Asn1Simple;
import org.apache.kerby.asn1.type.Asn1Type;
import org.apache.kerby.asn1.util.HexUtil;

import java.io.IOException;
import java.nio.ByteBuffer;

public final class Asn1Dumper {
    private boolean withType;
    private StringBuilder builder = new StringBuilder();

    public Asn1Dumper() {
        this.withType = true;
    }

    public Asn1Dumper(boolean withType) {
        this.withType = withType;
    }

    public boolean withType() {
        return withType;
    }

    public String output() {
        return builder.toString();
    }

    public void dumpWithHex(byte[] content,
                                  boolean useRawFormat) throws IOException {
        String hexStr = HexUtil.bytesToHex(content);
        append("Dumping data:").newLine();
        dumpData(hexStr);
        dump(content, useRawFormat);
    }

    public void dump(byte[] content,
                     boolean useRawFormat) throws IOException {
        dump(ByteBuffer.wrap(content), useRawFormat);
    }

    public void dump(ByteBuffer content,
                     boolean useRawFormat) throws IOException {
        if (useRawFormat) {
            Asn1ParseResult parseResult = Asn1Parser.parse(content);
            dumpParseResult(0, parseResult);
        } else {
            Asn1Type value = Asn1.decode(content);
            dumpType(0, value);
        }
    }

    public void dumpType(Asn1Type value) {
        dumpType(0, value);
    }

    public Asn1Dumper dumpType(int indents, Asn1Type value) {
        if (value == null) {
            indent(indents).append("Null");
        } else if (value instanceof Asn1Simple) {
            indent(indents).append(value.toString());
        } else if (value instanceof Asn1Dumpable) {
            Asn1Dumpable dumpable = (Asn1Dumpable) value;
            dumpable.dumpWith(this, indents);
        } else if (value instanceof Asn1Application) {
            indent(indents).append(value.toString());
        } else if (value instanceof Asn1Any) {
            indent(indents).append("<Any>");
        } else if (value instanceof Asn1Choice) {
            indent(indents).append("<Choice>");
        } else {
            indent(indents).append("<Unknown>");
        }

        return this;
    }

    public Asn1Dumper dumpParseResult(int indents, Asn1ParseResult value) {
        if (value == null) {
            indent(indents).append("Null");
        } else if (value instanceof Asn1Item) {
            indent(indents).append(value.toString());
        } else if (value instanceof Asn1Dumpable) {
            Asn1Dumpable dumpable = (Asn1Dumpable) value;
            dumpable.dumpWith(this, indents);
        } else {
            indent(indents).append("<Unknown>");
        }

        return this;
    }

    public Asn1Dumper indent(int numSpaces) {
        for (int i = 0; i < numSpaces; i++) {
            builder.append(' ');
        }
        return this;
    }

    public Asn1Dumper append(Asn1Simple<?> simpleValue) {
        if (simpleValue != null) {
            builder.append(simpleValue.toString());
        } else {
            builder.append("null");
        }
        return this;
    }

    public Asn1Dumper append(String string) {
        builder.append(string);
        return this;
    }

    public Asn1Dumper dumpTypeInfo(Class<?> cls) {
        appendType(cls).newLine();
        return this;
    }

    public Asn1Dumper dumpTypeInfo(int indents, Class<?> cls) {
        if (withType()) {
            indent(indents).appendType(cls).newLine();
        }
        return this;
    }

    private Asn1Dumper appendType(Class<?> cls) {
        builder.append("<").append(cls.getSimpleName()).append(">");
        return this;
    }

    public Asn1Dumper newLine() {
        builder.append("\n");
        return this;
    }

    public Asn1Dumper dumpData(String hexData) {
        int range = 100;
        int pos = range;

        while (pos < hexData.length()) {
            System.out.println(hexData.substring(pos - range, pos));
            pos = pos + range;
        }
        System.out.println(hexData.substring(pos - range, hexData.length()));

        return this;
    }
}
