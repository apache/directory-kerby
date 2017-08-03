/*
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
package org.apache.kerby.kerberos.kerb.crypto.dh;


import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;


/**
 * "When using the Diffie-Hellman key agreement method, implementations MUST
 * support Oakley 1024-bit Modular Exponential (MODP) well-known group 2
 * [RFC2412] and Oakley 2048-bit MODP well-known group 14 [RFC3526] and
 * SHOULD support Oakley 4096-bit MODP well-known group 16 [RFC3526]."
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DhGroup {
    /**
     * From:
     * The OAKLEY Key Determination Protocol
     * http://www.ietf.org/rfc/rfc2412.txt
     *
     * Well-Known Group 2:  A 1024 bit prime
     * This group is assigned id 2 (two).
     * The prime is 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }.
     * The generator is 2 (decimal)
     */
    public static final DHParameterSpec MODP_GROUP2;

    static {
        StringBuilder sb = new StringBuilder();
        sb.append("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1");
        sb.append("29024E088A67CC74020BBEA63B139B22514A08798E3404DD");
        sb.append("EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245");
        sb.append("E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED");
        sb.append("EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381");
        sb.append("FFFFFFFFFFFFFFFF");

        BigInteger prime = new BigInteger(sb.toString(), 16);
        BigInteger generator = BigInteger.valueOf(2);

        MODP_GROUP2 = new DHParameterSpec(prime, generator);
    }

    /**
     * From:
     * More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)
     * http://www.ietf.org/rfc/rfc3526.txt
     *
     * 2048-bit MODP Group
     * This group is assigned id 14.
     * This prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
     * The generator is: 2.
     */
    public static final DHParameterSpec MODP_GROUP14;

    static {
        StringBuilder sb = new StringBuilder();
        sb.append("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1");
        sb.append("29024E088A67CC74020BBEA63B139B22514A08798E3404DD");
        sb.append("EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245");
        sb.append("E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED");
        sb.append("EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D");
        sb.append("C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F");
        sb.append("83655D23DCA3AD961C62F356208552BB9ED529077096966D");
        sb.append("670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B");
        sb.append("E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9");
        sb.append("DE2BCBF6955817183995497CEA956AE515D2261898FA0510");
        sb.append("15728E5A8AACAA68FFFFFFFFFFFFFFFF");

        BigInteger prime = new BigInteger(sb.toString(), 16);
        BigInteger generator = BigInteger.valueOf(2);

        MODP_GROUP14 = new DHParameterSpec(prime, generator);
    }

    /**
     * From:
     * More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)
     * http://www.ietf.org/rfc/rfc3526.txt
     *
     * 4096-bit MODP Group
     * This group is assigned id 16.
     * This prime is: 2^4096 - 2^4032 - 1 + 2^64 * { [2^3966 pi] + 240904 }
     * The generator is: 2.
     */
    public static final DHParameterSpec MODP_GROUP16;

    static {
        StringBuilder sb = new StringBuilder();
        sb.append("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1");
        sb.append("29024E088A67CC74020BBEA63B139B22514A08798E3404DD");
        sb.append("EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245");
        sb.append("E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED");
        sb.append("EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D");
        sb.append("C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F");
        sb.append("83655D23DCA3AD961C62F356208552BB9ED529077096966D");
        sb.append("670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B");
        sb.append("E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9");
        sb.append("DE2BCBF6955817183995497CEA956AE515D2261898FA0510");
        sb.append("15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64");
        sb.append("ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7");
        sb.append("ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B");
        sb.append("F12FFA06D98A0864D87602733EC86A64521F2B18177B200C");
        sb.append("BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31");
        sb.append("43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7");
        sb.append("88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA");
        sb.append("2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6");
        sb.append("287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED");
        sb.append("1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9");
        sb.append("93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199");
        sb.append("FFFFFFFFFFFFFFFF");

        BigInteger prime = new BigInteger(sb.toString(), 16);
        BigInteger generator = BigInteger.valueOf(2);

        MODP_GROUP16 = new DHParameterSpec(prime, generator);
    }
}
