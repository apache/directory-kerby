/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl;

import org.apache.kerby.asn1.Asn1InputBuffer;
import org.apache.kerby.asn1.type.*;
import org.apache.kerby.util.Hex;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 16-Nov-2005
 */

/**
 * Adapted from ASN1Util in not-yet-commons-ssl
 */
public class Asn1PkcsUtil {

    public final static BigInteger BIGGEST =
            new BigInteger(Integer.toString(Integer.MAX_VALUE));

    public static Asn1PkcsStructure analyze(byte[] asn1)
            throws IOException {
        Asn1InputBuffer asn = new Asn1InputBuffer(asn1);
        Asn1Type asn1Obj;

        Asn1PkcsStructure pkcs8 = new Asn1PkcsStructure();
        while ((asn1Obj = asn.read()) != null) {
            if (asn1Obj instanceof Asn1Collection) {
                Asn1PkcsUtil.analyze((Asn1Collection) asn1Obj, pkcs8, 0);
            } else {
                Asn1PkcsUtil.analyze(asn1Obj, pkcs8, 0);
            }
        }

        return pkcs8;
    }

    public static void analyze(Asn1Collection asn1Coll, Asn1PkcsStructure pkcs8, int depth) {
        if (depth >= 2) {
            pkcs8.derIntegers = null;
        }

        List<Asn1Item> items = asn1Coll.getValue();
        for (Asn1Item item : items) {
            if (! item.isCollection()) {
                analyze(item.getValue(), pkcs8, depth);
            } else {
                try {
                    item.decodeValueAsCollection();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                analyze((Asn1Collection) item.getValue(), pkcs8, depth + 1);
            }
        }
    }

    public static void analyze(Asn1Type obj, Asn1PkcsStructure pkcs8, int depth) {
        String tag = null;
        if (depth >= 2) {
            pkcs8.derIntegers = null;
        }

        String str = obj.toString();
        String name = obj.getClass().getName();
        name = name.substring(name.lastIndexOf('.') + 1);
        if (tag != null) {
            name = " [tag=" + tag + "] " + name;
        }
        for (int i = 0; i < depth; i++) {
            name = "  " + name;
        }

        if (obj instanceof Asn1Integer) {
            Asn1Integer dInt = (Asn1Integer) obj;
            if (pkcs8.derIntegers != null) {
                pkcs8.derIntegers.add(dInt);
            }
            BigInteger big = dInt.getValue();
            int intValue = big.intValue();
            if (BIGGEST.compareTo(big) >= 0 && intValue > 0) {
                if (pkcs8.iterationCount == 0) {
                    pkcs8.iterationCount = intValue;
                } else if (pkcs8.keySize == 0) {
                    pkcs8.keySize = intValue;
                }
            }
        } else if (obj instanceof Asn1ObjectIdentifier) {
            Asn1ObjectIdentifier id = (Asn1ObjectIdentifier) obj;
            str = id.getValue();
            pkcs8.oids.add(str);
            if (pkcs8.oid1 == null) {
                pkcs8.oid1 = str;
            } else if (pkcs8.oid2 == null) {
                pkcs8.oid2 = str;
            } else if (pkcs8.oid3 == null) {
                pkcs8.oid3 = str;
            }
        } else {
            pkcs8.derIntegers = null;
            if (obj instanceof Asn1OctetString) {
                Asn1OctetString oct = (Asn1OctetString) obj;
                byte[] octets = oct.getValue();
                int len = Math.min(10, octets.length);
                boolean probablyBinary = false;
                for (int i = 0; i < len; i++) {
                    byte b = octets[i];
                    boolean isBinary = b > 128 || b < 0;
                    if (isBinary) {
                        probablyBinary = true;
                        break;
                    }
                }
                if (probablyBinary && octets.length > 64) {
                    if (pkcs8.bigPayload == null) {
                        pkcs8.bigPayload = octets;
                    }
                } else {
                    str = Hex.encode(octets);
                    if (octets.length <= 64) {
                        if (octets.length % 8 == 0) {
                            if (pkcs8.salt == null) {
                                pkcs8.salt = octets;
                            } else if (pkcs8.iv == null) {
                                pkcs8.iv = octets;
                            }
                        } else {
                            if (pkcs8.smallPayload == null) {
                                pkcs8.smallPayload = octets;
                            }
                        }
                    }
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        FileInputStream in = new FileInputStream(args[0]);
        byte[] bytes = Util.streamToBytes(in);
        List list = PEMUtil.decode(bytes);
        if (!list.isEmpty()) {
            bytes = ((PEMItem) list.get(0)).getDerBytes();
        }

        Asn1PkcsStructure asn1 = analyze(bytes);
        while (asn1.bigPayload != null) {
            System.out.println("------------------------------------------");
            System.out.println(asn1);
            System.out.println("------------------------------------------");
            asn1 = analyze(asn1.bigPayload);
        }
    }
}
