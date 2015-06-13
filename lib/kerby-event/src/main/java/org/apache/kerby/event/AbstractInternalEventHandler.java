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
package org.apache.kerby.event;

import java.util.concurrent.atomic.AtomicInteger;

public abstract class AbstractInternalEventHandler extends AbstractEventHandler
        implements InternalEventHandler {

    private int id = -1;
    protected EventHandler handler;

    private static AtomicInteger idGen = new AtomicInteger(1);

    public AbstractInternalEventHandler() {
        super();

        this.id = idGen.getAndIncrement();

        init();
    }

    public AbstractInternalEventHandler(EventHandler handler) {
        this();

        this.handler = handler;
    }

    protected void setEventHandler(EventHandler handler) {
        this.handler = handler;
    }

    @Override
    public int id() {
        return id;
    }

    public abstract void init();

    protected void process(Event event) {
        handler.handle(event);
    }

    @Override
    public EventType[] getInterestedEvents() {
        return handler.getInterestedEvents();
    }
}

