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
    private boolean requireEku = true;
    // accept secondary EKU (default is false)
    private boolean acceptSecondaryEku = false;
    // allow UPN-SAN instead of pkinit-SAN
    private boolean allowUpn = true;
    // selects DH or RSA based pkinit
    private boolean usingRsa = false;
    // require CRL for a CA (default is false)
    private boolean requireCrlChecking = false;
    // initial request DH modulus size (default=1024)
    private int dhSize = 1024;

    private boolean requireHostnameMatch = true;

    public boolean isRequireEku() {
        return requireEku;
    }

    public void setRequireEku(boolean requireEku) {
        this.requireEku = requireEku;
    }

    public boolean isAcceptSecondaryEku() {
        return acceptSecondaryEku;
    }

    public void setAcceptSecondaryEku(boolean acceptSecondaryEku) {
        this.acceptSecondaryEku = acceptSecondaryEku;
    }

    public boolean isAllowUpn() {
        return allowUpn;
    }

    public void setAllowUpn(boolean allowUpn) {
        this.allowUpn = allowUpn;
    }

    public boolean isUsingRsa() {
        return usingRsa;
    }

    public void setUsingRsa(boolean usingRsa) {
        this.usingRsa = usingRsa;
    }

    public boolean isRequireCrlChecking() {
        return requireCrlChecking;
    }

    public void setRequireCrlChecking(boolean requireCrlChecking) {
        this.requireCrlChecking = requireCrlChecking;
    }

    public int getDhSize() {
        return dhSize;
    }

    public void setDhSize(int dhSize) {
        this.dhSize = dhSize;
    }

    public boolean isRequireHostnameMatch() {
        return requireHostnameMatch;
    }

    public void setRequireHostnameMatch(boolean requireHostnameMatch) {
        this.requireHostnameMatch = requireHostnameMatch;
    }
}
