/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.kerby;

import java.util.Comparator;

import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;

/**
 * Comparator for KrbIdentity
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class KrbIdentityComparator implements Comparator<KrbIdentity> {

    public static final KrbIdentityComparator INSTANCE = new KrbIdentityComparator();

    private KrbIdentityComparator() {
    }

    @Override
    public int compare(KrbIdentity o1, KrbIdentity o2) {
        return o1.getPrincipalName().compareTo(o2.getPrincipalName());
    }

}
