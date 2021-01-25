package cn.ctyun.oos.iam.accesscontroller.cache;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

public class SemaphoreDataLoaderTest {

    private int threadCount = 1000;
    private volatile boolean contain = false;
    
    DataLoader<String> futureLoader = new SemaphoreDataLoader<String>() {
        @Override
        public String loadAndSet(String key) {
            String threadName = Thread.currentThread().getName();
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            return threadName + "_" + key + "_loaded";
        }
        @Override
        public boolean contains(String key) {
            return contain;
        }
        @Override
        public String fromCache(String key) {
            return key;
        }
    };
    
    @Test
    public void testGet() throws InterruptedException {
        ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        contain = false;
        for (int i = 0; i < threadCount; i++) {
            executorService.execute(() -> {
                try {
                    futureLoader.get("test1");
                    contain = true;
                } catch (IOException e) {
                }
            });
        }
        executorService.shutdown();
        try {
            executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
        }
    }

    
    @Test
    public void testGet1() throws InterruptedException {
        ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        contain = false;
        for (int i = 0; i < threadCount; i++) {
            executorService.execute(() -> {
                try {
                    futureLoader.get("test");
                    contain = true;
                } catch (IOException e) {
                }
            });
        }
        executorService.shutdown();
        try {
            executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
        }
    }
    
    @Test
    public void testGet2() throws InterruptedException {
        ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        contain = false;
        for (int i = 0; i < threadCount; i++) {
            executorService.execute(() -> {
                try {
                    futureLoader.get("test");
                    contain = true;
                } catch (IOException e) {
                }
            });
        }
        executorService.shutdown();
        try {
            executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
        }
    }
}
