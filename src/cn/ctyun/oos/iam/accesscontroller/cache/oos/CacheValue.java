package cn.ctyun.oos.iam.accesscontroller.cache.oos;

import java.util.concurrent.atomic.AtomicLong;

/**
 * 缓存的值
 * @author wangduo
 *
 * @param <V>
 */
public class CacheValue<V> {
    
    public V value;
    
    public AtomicLong lastVisit = new AtomicLong(System.currentTimeMillis());
    
    public CacheValue(Object key, V value) {
        this.value = value;
    }
}