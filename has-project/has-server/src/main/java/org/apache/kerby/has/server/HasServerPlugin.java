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
package org.apache.kerby.has.server;

import org.apache.kerby.kerberos.kerb.type.base.AuthToken;

public interface HasServerPlugin {
        /**
         * Get the login module type ID, used to distinguish this module from others.
         * Should correspond to the client side module.
         *
         * @return login type
         */
        String getLoginType();

        /**
         * Perform all the server side authentication logics, the results wrapped in an AuthToken,
         * will be used to exchange a Kerberos ticket.
         *
         * @param userToken user token
         * @return auth token
         */
        AuthToken authenticate(AuthToken userToken) throws HasAuthenException;
}
