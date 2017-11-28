/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kerby.has.common;

public class HasException extends Exception {

    private static final long serialVersionUID = -1916788959202646914L;

    /**
     * Creates an {@link HasException}.
     *
     * @param cause original exception.
     */
    public HasException(Throwable cause) {
        super(cause);
    }

    /**
     * Creates an {@link HasException}.
     *
     * @param message exception message.
     */
    public HasException(String message) {
        super(message);
    }

    /**
     * Creates an {@link HasException}.
     *
     * @param message exception message.
     * @param cause   original exception.
     */
    public HasException(String message, Throwable cause) {
        super(message, cause);
    }

}
