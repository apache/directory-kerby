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

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * An EventHandler wrapper processing events using an ExecutorService
 */
public class ExecutedEventHandler extends AbstractInternalEventHandler {

    private ExecutorService executorService;

    public ExecutedEventHandler(EventHandler handler) {
        super(handler);
    }

    @Override
    protected void doHandle(final Event event) throws Exception {
        if (executorService.isTerminated()) {
            return;
        }

        executorService.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    process(event);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }

    @Override
    public void start() {
        executorService = Executors.newFixedThreadPool(2);
    }

    @Override
    public void stop() {
        if (executorService.isShutdown()) {
            return;
        }
        executorService.shutdownNow();
    }

    @Override
    public boolean isStopped() {
        return executorService.isShutdown();
    }

    @Override
    public void init() {

    }
}