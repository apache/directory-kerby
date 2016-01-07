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

import org.junit.Test;

import static org.apache.kerby.util.IPAddressParser.parseIPv4Literal;
import static org.apache.kerby.util.IPAddressParser.parseIPv6Literal;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;

public class IPAddressParserTest {

    @Test
    public void theTest() {

        // bad ones
        assertNull("ip6 invalid", parseIPv6Literal(":::"));
        assertNull("ip6 too many zero-expanders", parseIPv6Literal("1::1::"));
        assertNull("ip6 .256 invalid", parseIPv6Literal("1::1:255.254.253.256"));
        assertNull("ip6 too small", parseIPv6Literal("1:2:3:4"));
        assertNull("ip6 no zero-expander after ip4", parseIPv6Literal("1:255.254.253.252::"));
        assertNull("ip6 no zero-expander if 7 colons (end)", parseIPv6Literal("1:2:3:4:5:6:7:8::"));
        assertNull("ip6 no zero-expander if 7 colons (begin)", parseIPv6Literal("::1:2:3:4:5:6:7:8"));
        assertNull("ip6 88888 too many digits", parseIPv6Literal("1:2:3:4:5:6:7:88888"));
        assertNull("ip6 missing colons", parseIPv6Literal("abcd"));
        assertNull("ip6 umm, no", parseIPv6Literal("cookie monster"));
        assertNull("ip6 empty string is invalid", parseIPv6Literal(""));
        assertNull("ip6 null is invalid", parseIPv6Literal(null));

        assertNull("ip4 not enough dots", parseIPv4Literal("abcd"));
        assertNull("ip4 umm, no", parseIPv4Literal("cookie monster"));
        assertNull("ip4 empty string is invalid", parseIPv4Literal(""));
        assertNull("ip4 null is invalid", parseIPv4Literal(null));
        assertNull("ip4 not enough dots 0", parseIPv4Literal("1"));
        assertNull("ip4 not enough dots 1", parseIPv4Literal("1.2"));
        assertNull("ip4 not enough dots 2", parseIPv4Literal("1.2.3"));
        assertNull("ip4 needs digit after final dot", parseIPv4Literal("1.2.3."));
        assertNull("ip4 [0-9] digits only", parseIPv4Literal("1.2.3.a"));
        assertNull("ip4 too many dots", parseIPv4Literal("1.2.3.4.5"));
        assertNull("ip4 0-255 range", parseIPv4Literal("1.2.3.444"));
        assertNull("ip4 no negatives", parseIPv4Literal("1.2.-3.4"));
        assertNull("ip4 no brackets", parseIPv4Literal("[1.2.3.4]"));

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
