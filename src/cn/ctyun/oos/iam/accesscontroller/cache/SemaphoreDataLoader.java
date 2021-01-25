package cn.ctyun.oos.iam.accesscontroller.cache;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * 使用信号量的方式防止并发访问数据库
 * @author wangduo
 *
 * @param <T>
 */
public abstract class SemaphoreDataLoader<T> implements DataLoader<T> {

    private static final Log log = LogFactory.getLog(SemaphoreDataLoader.class);
    
    private final Map<String, Semaphore> keySemaphores = new ConcurrentHashMap<>();
    
    @Override
    public T get(String key) throws IOException {
        // 单条数据获取，缓存中获取不到数据，获取key对应的信号量，防止单用户多个请求，并发查询数据库
        if (!contains(key)) {
            // 对同一个key的数据加载允许三个并发
            Semaphore semaphore = keySemaphores.computeIfAbsent(key, k -> new Semaphore(3));
            try {
                try {
                    semaphore.acquire();
                } catch (InterruptedException e) {
                    log.error("thread Interrupted", e);
                    throw new RuntimeException(e);
                }
                // 如果已经被加载过，从缓存中加载
                if (contains(key)) {
                    fromCache(key);
                }
                return loadAndSet(key);
            } finally {
                semaphore.release();
                // 如何缓存中已有数据，移除信号量
                if (contains(key)) {
                    keySemaphores.remove(key);
                }
            }
        } else {
            // 缓存中有数据，从缓存中加载
            return fromCache(key);
        }
    }
    
}
