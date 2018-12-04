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

package org.apache.kerby.has.client;

import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;

public interface HasClientPlugin {

    /**
     * Get the login module type ID, used to distinguish this module from others.
     * Should correspond to the server side module.
     *
     * @return login type
     */
    String getLoginType();

    /**
     * Perform all the client side login logics, the results wrapped in an AuthToken,
     * will be validated by HAS server.
     *
     * @param conf token plugin config
     * @return user auth token
     * @throws HasLoginException HAS login exception
     */
    AuthToken login(HasConfig conf) throws HasLoginException;
}
