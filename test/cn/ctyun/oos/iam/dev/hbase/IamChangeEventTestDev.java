package cn.ctyun.oos.iam.dev.hbase;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor.CallerRunsPolicy;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.metadata.IamChangeEvent;
import cn.ctyun.oos.metadata.IamChangeEvent.ChangeType;

public class IamChangeEventTestDev {

    MetaClient metaClient = MetaClient.getGlobalClient(); 
    @Test
    public void testInsert() throws IOException {
        for (int i = 1; i <= 100000; i++) {
            metaClient.iamChangeEventInsert(new IamChangeEvent(ChangeType.ACCESSKEY, "2ccbb11aa11" + i, "222222222222222"));
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        
    }
    
    @Test
    public void testList() {
        int nThreads = 500;
        ExecutorService executorService = new ThreadPoolExecutor(nThreads, nThreads,
                0L, TimeUnit.MILLISECONDS,
                new SynchronousQueue<Runnable>(), new CallerRunsPolicy()); 
        while (true) {
            try {
                Thread.sleep(60);
            } catch (InterruptedException e1) {
                e1.printStackTrace();
            }
            executorService.submit(() -> {
                try {
                    long start = System.currentTimeMillis();
                    List<IamChangeEvent> events = metaClient.iamChangeEventList(System.currentTimeMillis() - 90000);
                    System.out.println("size : " +  events.size() + ", use time : " + (System.currentTimeMillis() - start));
                    Thread.sleep(30000);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
        
//        try {
//            Thread.sleep(100000);
//        } catch (InterruptedException e) {
//            e.printStackTrace();
//        }
    }
}
