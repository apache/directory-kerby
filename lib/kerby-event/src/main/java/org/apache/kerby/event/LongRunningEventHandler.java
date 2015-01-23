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

public abstract class LongRunningEventHandler extends BufferedEventHandler {

    private ExecutorService executorService;

    public LongRunningEventHandler(EventHandler handler) {
        super(handler);
    }

    public LongRunningEventHandler() {
        super();
    }

    protected abstract void loopOnce();

    @Override
    public void start() {
        executorService = Executors.newFixedThreadPool(1);
        executorService.execute(new Runnable() {
            @Override
            public void run() {
                while (true) {

                    processEvents();

                    loopOnce();
                }
            }
        });
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

    protected void processEvents() {
        while (! eventQueue.isEmpty()) {
            try {
                process(eventQueue.take());
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }
}