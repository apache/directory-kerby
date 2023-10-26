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
package org.apache.kerby.util;

import org.junit.jupiter.api.Test;

import static org.apache.kerby.util.IPAddressParser.parseIPv4Literal;
import static org.apache.kerby.util.IPAddressParser.parseIPv6Literal;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class IPAddressParserTest {

    @Test
    public void theTest() {

        // bad ones
        assertNull(parseIPv6Literal(":::"), "ip6 invalid");
        assertNull(parseIPv6Literal("1::1::"), "ip6 too many zero-expanders");
        assertNull(parseIPv6Literal("1::1:255.254.253.256"), "ip6 .256 invalid");
        assertNull(parseIPv6Literal("1:2:3:4"), "ip6 too small");
        assertNull(parseIPv6Literal("1:255.254.253.252::"), "ip6 no zero-expander after ip4");
        assertNull(parseIPv6Literal("1:2:3:4:5:6:7:8::"), "ip6 no zero-expander if 7 colons (end)");
        assertNull(parseIPv6Literal("::1:2:3:4:5:6:7:8"), "ip6 no zero-expander if 7 colons (begin)");
        assertNull(parseIPv6Literal("1:2:3:4:5:6:7:88888"), "ip6 88888 too many digits");
        assertNull(parseIPv6Literal("abcd"), "ip6 missing colons");
        assertNull(parseIPv6Literal("cookie monster"), "ip6 umm, no");
        assertNull(parseIPv6Literal(""), "ip6 empty string is invalid");
        assertNull(parseIPv6Literal(null), "ip6 null is invalid");

        assertNull(parseIPv4Literal("abcd"), "ip4 not enough dots");
        assertNull(parseIPv4Literal("cookie monster"), "ip4 umm, no");
        assertNull(parseIPv4Literal(""), "ip4 empty string is invalid");
        assertNull(parseIPv4Literal(null), "ip4 null is invalid");
        assertNull(parseIPv4Literal("1"), "ip4 not enough dots 0");
        assertNull(parseIPv4Literal("1.2"), "ip4 not enough dots 1");
        assertNull(parseIPv4Literal("1.2.3"), "ip4 not enough dots 2");
        assertNull(parseIPv4Literal("1.2.3."), "ip4 needs digit after final dot");
        assertNull(parseIPv4Literal("1.2.3.a"), "ip4 [0-9] digits only");
        assertNull(parseIPv4Literal("1.2.3.4.5"), "ip4 too many dots");
        assertNull(parseIPv4Literal("1.2.3.444"), "ip4 0-255 range");
        assertNull(parseIPv4Literal("1.2.-3.4"), "ip4 no negatives");
        assertNull(parseIPv4Literal("[1.2.3.4]"), "ip4 no brackets");

        // good ones
        assertArrayEquals(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, parseIPv6Literal("::"));
        assertArrayEquals(new byte[]{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, parseIPv6Literal("1::"));
        assertArrayEquals(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, parseIPv6Literal("::1"));
        assertArrayEquals(new byte[]{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, parseIPv6Literal("1::1"));
        assertArrayEquals(new byte[]{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, parseIPv6Literal("100::1"));

        assertArrayEquals(new byte[]{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, -1, -2, -3, -4},
                parseIPv6Literal("1::1:255.254.253.252"));

        assertArrayEquals(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -2, -3, -4},
                parseIPv6Literal("::255.254.253.252"));

        assertArrayEquals(new byte[]{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, -1, -2, -3, -4},
                parseIPv6Literal("1:2:3:4:5:6:255.254.253.252"));

        assertArrayEquals(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4}, parseIPv6Literal("::1:2:3:4"));
        assertArrayEquals(new byte[]{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 3, 0, 4}, parseIPv6Literal("1::2:3:4"));
        assertArrayEquals(new byte[]{0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 4}, parseIPv6Literal("1:2::3:4"));
        assertArrayEquals(new byte[]{0, 1, 0, 2, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}, parseIPv6Literal("1:2:3::4"));
        assertArrayEquals(new byte[]{0, 1, 0, 2, 0, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0}, parseIPv6Literal("1:2:3:4::"));

        assertArrayEquals(new byte[]{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8},
                parseIPv6Literal("1:2:3:4:5:6:7:8"));

        assertArrayEquals(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, parseIPv6Literal("[::]"));

        assertArrayEquals(new byte[]{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8},
                parseIPv6Literal("[1:2:3:4:5:6:7:8]"));

        assertArrayEquals(new byte[]{17, 17, 34, 34, 51, 51, 68, 68, 85, 85, 102, 102, 119, 119, -120, -120},
                parseIPv6Literal("1111:2222:3333:4444:5555:6666:7777:8888"));

        assertArrayEquals(new byte[]{0, 0, 0, 0}, parseIPv4Literal("0.0.0.0"));
        assertArrayEquals(new byte[]{1, 2, 3, 4}, parseIPv4Literal("1.2.3.4"));
        assertArrayEquals(new byte[]{-1, -1, -1, -1}, parseIPv4Literal("255.255.255.255"));
    }
}
