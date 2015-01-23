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
package org.apache.kerby.kerberos.kerb.client.preauth.pkinit;

public class PkinitRequestOpts {

    // From MIT Krb5 _pkinit_plg_opts

    // require EKU checking (default is true)
    public boolean requireEku = true;
    // accept secondary EKU (default is false)
    public boolean acceptSecondaryEku = false;
    // allow UPN-SAN instead of pkinit-SAN
    public boolean allowUpn = true;
    // selects DH or RSA based pkinit
    public boolean usingRsa = true;
    // require CRL for a CA (default is false)
    public boolean requireCrlChecking = false;
    // initial request DH modulus size (default=1024)
    public int dhSize = 1024;

    public boolean requireHostnameMatch = true;
}
