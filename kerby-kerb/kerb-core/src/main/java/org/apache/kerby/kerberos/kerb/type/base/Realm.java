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
package org.apache.kerby.kerberos.kerb.type.base;

import org.apache.kerby.kerberos.kerb.type.KerberosString;

/**
 * The Realm, as defined by RFC 4120 :
 * 
 * <pre>
 * Realm           ::= KerberosString
 * </pre>
 * 
 * There are some restrictions on the realm name : 
 * <ul>
 *   <li>The '0x00' char is not allowed</li>
 *   <li>
 *     The realm itself must enter into one of the three categories :
 *     <ul>
 *       <li>
 *         domain :<br>
 *         &lt;domain&gt; ::= &lt;component&gt; [ '.' &lt;component&gt;]*<br>
 *         &lt;component&gt; ::= [any KerberosString char but '0x00', '/' or ':']<br>
 *       </li>
 *       <li>X500 :<br>
 *         &lt;X500&gt; ::= &lt;X500component&gt; [ '/' &lt;X500component&gt;]*<br>
 *         &lt;X500component&gt; ::= &lt;leftPart&gt; '=' &lt;rightPart&gt;<br>
 *         &lt;leftPart&gt; ::= [any KerberosString char but '0x00', '/'  or ':']<br>
 *         &lt;rightPart&gt; ::= [any KerberosString char but '0x00' or '/']
 *       </li>
 *       <li>
 *         Other :<br> 
 *         &lt;other&gt; ::= &lt;prefix&gt; ':' &lt;rest of the name&gt;<br>
 *         &lt;prefix&gt; ::= [any KerberosString char but '0x00', '.' or '=']<br>
 *         &lt;rest of the name&gt; ::= [any KerberosString char but '0x00']
 *       </li>
 *     </ul>
 *   </li>
 * </ul> 
 * 
 * Technically, we can detect the Realm's type by checking the presence of '/', '.' and ':'.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class Realm extends KerberosString {
    /**
     * Creates a new Realm instance
     */
    public Realm() {
    }

    /**
     * Creates a new Realm instance with a value
     * 
     * @param value the Realm value
     */
    public Realm(String value) {
        super(value);
        
        // TODO : check that it's a valid REALM...
    }
}
