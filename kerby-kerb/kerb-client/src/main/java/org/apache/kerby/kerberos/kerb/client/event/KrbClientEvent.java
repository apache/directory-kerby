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
package org.apache.kerby.kerberos.kerb.client.event;

import org.apache.kerby.event.Event;
import org.apache.kerby.kerberos.kerb.client.request.AsRequest;
import org.apache.kerby.kerberos.kerb.client.request.TgsRequest;

public class KrbClientEvent {

    public static Event createTgtIntentEvent(AsRequest asRequest) {
        return new Event(KrbClientEventType.TGT_INTENT, asRequest);
    }

    public static Event createTktIntentEvent(TgsRequest tgsRequest) {
        return new Event(KrbClientEventType.TKT_INTENT, tgsRequest);
    }

    public static Event createTgtResultEvent(AsRequest asRequest) {
        return new Event(KrbClientEventType.TGT_RESULT, asRequest);
    }

    public static Event createTktResultEvent(TgsRequest tgsRequest) {
        return new Event(KrbClientEventType.TKT_RESULT, tgsRequest);
    }
}
