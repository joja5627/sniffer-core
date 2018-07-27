/**
 * Copyright (c) 2014-2017 by the respective copyright holders.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.network.core.pcap;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ThreadPoolManager{

    protected static final int  CORE_COUNT = Runtime.getRuntime().availableProcessors();

    protected static final int DEFAULT_THREAD_POOL_SIZE = CORE_COUNT - 2;

    protected static final long THREAD_TIMEOUT = 65L;

    protected static class NamedThreadFactory implements ThreadFactory{

        public class Task implements Runnable {

            private PcapHandle handle;
            private PacketListener listener;

            public Task(PcapHandle handle, PacketListener listener) {
                this.handle = handle;
                this.listener = listener;
            }

            @Override
            public void run() {
                try {
                    handle.loop(-1, listener);
                } catch (PcapNativeException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } catch (NotOpenException e) {
                    e.printStackTrace();
                }
            }

        }


    static public ScheduledExecutorService getScheduledPool(String poolName){
        ScheduledExecutorService pool = Executors.newScheduledThreadPool(DEFAULT_THREAD_POOL_SIZE,
                new NamedThreadFactory(poolName));
        ((ThreadPoolExecutor)pool).setKeepAliveTime(THREAD_TIMEOUT, TimeUnit.SECONDS);
        ((ThreadPoolExecutor)pool).allowCoreThreadTimeOut(true);
        return pool;
    }




        protected final ThreadGroup group;
        protected final AtomicInteger threadNumber = new AtomicInteger(1);
        protected final String namePrefix;
        protected final String name;

        private PcapHandle handle;
        private PacketListener listener;

        public NamedThreadFactory(String threadPool){
            this.name = threadPool;
            this.namePrefix = "network-core-" + threadPool + "-";
            SecurityManager s = System.getSecurityManager();
            group = (s != null) ? s.getThreadGroup() : Thread.currentThread().getThreadGroup();
        }

        @Override
        public Thread newThread(Runnable r){
            Thread t = new Thread(group, r, namePrefix + threadNumber.getAndIncrement(), 0);
            if (!t.isDaemon()){
                t.setDaemon(true);
            }
            if (t.getPriority() != Thread.NORM_PRIORITY){
                t.setPriority(Thread.NORM_PRIORITY);
            }

            return t;
        }

        public String getName()
        {
            return name;
        }
    }
}
