/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.has.server;

import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractHasServerPlugin implements HasServerPlugin {

    public static final Logger LOG = LoggerFactory.getLogger(AbstractHasServerPlugin.class);

    protected abstract void doAuthenticate(AuthToken userToken, AuthToken authToken)
        throws HasAuthenException;

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthToken authenticate(AuthToken userToken) throws HasAuthenException {

        AuthToken authToken = KrbRuntime.getTokenProvider("JWT").createTokenFactory().createToken();

        doAuthenticate(userToken, authToken);

        return authToken;
    }

}
