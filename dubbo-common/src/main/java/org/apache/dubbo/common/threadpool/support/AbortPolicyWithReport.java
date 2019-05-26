/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.dubbo.common.threadpool.support;

import org.apache.dubbo.common.Constants;
import org.apache.dubbo.common.URL;
import org.apache.dubbo.common.logger.Logger;
import org.apache.dubbo.common.logger.LoggerFactory;
import org.apache.dubbo.common.utils.JVMUtil;

import java.io.File;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ExecutorService;

/**
 * Abort Policy.
 * Log warn info when abort.
 */
public class AbortPolicyWithReport extends ThreadPoolExecutor.AbortPolicy {

    protected static final Logger logger = LoggerFactory.getLogger(AbortPolicyWithReport.class);

    /**
     * 线程名
     */
    private final String threadName;
    /**
     * URL 对象
     */
    private final URL url;
    /**
     * 最后打印时间
     */
    private static volatile long lastPrintTime = 0;
    /**
     * 信号量，大小为 1 。
     * Semaphore可以控制同时访问的线程个数，通过 acquire() 获取一个许可，如果没有就等待，而 release() 释放一个许可。
     * 此处只有一个许可，说简单点，Semaphore维护了一个许可集合，在创建Semaphore的时候，设置上许可数，
     * 每条线程在只有在获得一个许可的时候才可以继续往下执行逻辑（申请一个许可，则Semaphore的许可池中减少一个许可），没有获得许可的线程会进入阻塞状态
     * 这里信号量是1，保证同一时间，有且仅有一个线程执行打印
     */
    private static Semaphore guard = new Semaphore(1);

    public AbortPolicyWithReport(String threadName, URL url) {
        this.threadName = threadName;
        this.url = url;
    }

    @Override
    public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
        // 打印告警日志
        String msg = String.format("Thread pool is EXHAUSTED!" +
                        " Thread Name: %s, Pool Size: %d (active: %d, core: %d, max: %d, largest: %d), Task: %d (completed: %d)," +
                        " Executor status:(isShutdown:%s, isTerminated:%s, isTerminating:%s), in %s://%s:%d!",
                threadName, e.getPoolSize(), e.getActiveCount(), e.getCorePoolSize(), e.getMaximumPoolSize(), e.getLargestPoolSize(),
                e.getTaskCount(), e.getCompletedTaskCount(), e.isShutdown(), e.isTerminated(), e.isTerminating(),
                url.getProtocol(), url.getIp(), url.getPort());
        logger.warn(msg);
        // 打印 JStack ，分析线程状态。
        dumpJStack();
        // 抛出 RejectedExecutionException 异常
        throw new RejectedExecutionException(msg);
    }

    private void dumpJStack() {
        long now = System.currentTimeMillis();

        //dump every 10 minutes
        // 每 10 分钟，打印一次。
        if (now - lastPrintTime < 10 * 60 * 1000) {
            return;
        }

        // 获得信号量 获得许可
        //获得信号量。保证同一时间，有且仅有一个线程执行打印
        if (!guard.tryAcquire()) {
            return;
        }

        // 创建线程池，后台执行打印 JStack
        ExecutorService pool = Executors.newSingleThreadExecutor();
        pool.execute(() -> {
            // 获得路径
            String dumpPath = url.getParameter(Constants.DUMP_DIRECTORY, System.getProperty("user.home"));

            SimpleDateFormat sdf;
            // 获得系统
            String os = System.getProperty("os.name").toLowerCase();

            // window system don't support ":" in file name
            if (os.contains("win")) {
                sdf = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss");
            } else {
                sdf = new SimpleDateFormat("yyyy-MM-dd_HH:mm:ss");
            }

            String dateStr = sdf.format(new Date());
            //try-with-resources
            try (FileOutputStream jStackStream = new FileOutputStream(new File(dumpPath, "Dubbo_JStack.log" + "." + dateStr))) {
                // 打印 JStack
                JVMUtil.jstack(jStackStream);
            } catch (Throwable t) {
                logger.error("dump jStack error", t);
            } finally {
                guard.release();
            }
            lastPrintTime = System.currentTimeMillis();
        });
        //must shutdown thread pool ,if not will lead to OOM
        pool.shutdown();

    }

}
