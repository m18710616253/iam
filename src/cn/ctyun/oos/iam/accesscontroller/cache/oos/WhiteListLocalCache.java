package cn.ctyun.oos.iam.accesscontroller.cache.oos;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import cn.ctyun.common.conf.GlobalIamConfig;
import cn.ctyun.common.conf.OOSConfig;

/**
 * 具有白名单的本地缓存
 * 缓存容量超过上限，跳过白名单对应的缓存进行清理
 * @author wangduo
 *
 */
public abstract class WhiteListLocalCache<K, V> {

    private static Log log = LogFactory.getLog(WhiteListLocalCache.class);
    
    protected final LinkedHashMap<K, CacheValue<V>> cacheMap;
    
    private final Map<K, Object> keyLocks = new ConcurrentHashMap<>();
    
    protected void init(){
    }
    
    public WhiteListLocalCache() {
        cacheMap = new LinkedHashMap<K, CacheValue<V>>() {
            
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(java.util.Map.Entry<K, CacheValue<V>> eldest) {
                Iterator<K> iterator = cacheMap.keySet().iterator();
                while (size() - getSizeLimit() > 0 && iterator.hasNext()) {
                    Object key = iterator.next();
                    // 不清除白名单中的缓存
                    if (inWhiteList(key.toString())) {
                        continue;
                    }
                    cacheMap.remove(key);
                    log.info(this.getClass().getSimpleName() + " size larger than " + getSizeLimit() + ", remove key " + key);
                }
                return false;
            }
        };
        init();
    }
    
    /**
     * 获取缓存个数的限制
     * @return
     */
    protected int getSizeLimit() {
        return OOSConfig.getLocalCacheMapSize();
    }
    
    /**
     * 加载数据
     * @param key
     * @throws IOException 
     */
    abstract V load(K key) throws IOException;
    
    /**
     * 重新加载数据
     * @param key
     * @throws IOException 
     */
    public void reload(K key) throws IOException {
        CacheValue<V> cache = getCacheValue(key);
        if (cache == null) {
            // 如果cache不存在，判断当前时候有线程正在获取
            Object lock = keyLocks.get(key);
            if (lock != null) {
                // 如果有线程正在获取，等待获取完成
                synchronized (lock) {
                }
            }
            // 在获取锁对象的过程中，缓存也可能会被赋值
            // 再次获取缓存
            cache = getCacheValue(key);
            // 如果缓存仍为空，不做更新处理
            if (cache == null) {
                return;
            }
        }
        // 更新缓存
        cache.value = load(key);
    }
    
    /**
     * 判断key是否在白名单中
     * @param key 
     * @return
     */
    public boolean inWhiteList(String key) {
        if (StringUtils.isEmpty(key)) {
            return false;
        }
        HashSet<String> whiteList = GlobalIamConfig.getPolicyCacheWhiteList();
        // 用户key在白名单中
        if (whiteList.contains(key)) {
            return true;
        }
        String[] keySplits = key.split("\\|");
        // 用户的accountId在白名单中
        if (whiteList.contains(keySplits[0])) {
            return true;
        }
        return false;
    }
    
    /**
     * 清除所有缓存
     */
    public synchronized void invalidateAll() {
        cacheMap.clear();
    }
    
    /**
     * 清除指定缓存
     * @param key
     */
    public synchronized void invalidate(K key) {
        cacheMap.remove(key);
    }
    
    /**
     * 添加缓存
     * @param key
     * @param value
     */
    private synchronized CacheValue<V> put(K key, V value) {
        CacheValue<V> cacheValue = new CacheValue<>(key, value);
        cacheMap.put(key, cacheValue);
        return cacheValue;
    }
    
    /**
     * 缓存中有，从缓存中获取
     * 缓存中没有，调用loadData方法
     * @param key
     * @return
     * @throws IOException 
     */
    public V get(K key) throws IOException {
        // 如果配置了不使用缓存，直接加载数据
        if (!GlobalIamConfig.isUseCache()) {
            return load(key);
        }
        CacheValue<V> cache = getCacheValue(key);
        if(cache == null) {
            Object lock = keyLocks.computeIfAbsent(key, k -> new Object());
            try {
                // 防止并发访问数据库加载数据
                synchronized (lock) {
                    cache = getCacheValue(key);
                    if (cache == null) {
                        V value = load(key);
                        cache = put(key, value);
                    }
                }
            } finally {
                keyLocks.remove(lock);
            }
        }
        cache.lastVisit.set(System.currentTimeMillis());
        return cache.value;
    }
    
    /**
     * 获取缓存信息
     * @param key
     * @return
     */
    public synchronized CacheValue<V> getCacheValue(K key) {
        return cacheMap.get(key);
    }
    
    /**
     * 数据过期处理
     */
    public synchronized void expire() {
        List<K> removeKeys = new ArrayList<>();
        for (Entry<K, CacheValue<V>> entry : cacheMap.entrySet()) {
            long lastVisitTime = entry.getValue().lastVisit.get();
            // 不在白名单且过期，清除缓存
            if (!inWhiteList(entry.getKey().toString()) && ((System.currentTimeMillis() - lastVisitTime) > GlobalIamConfig.getCacheExpireTime())) {
                // 记录需要清理的key
                removeKeys.add(entry.getKey());
            }
        }
        // 对过期的缓存进行清理
        for (K key : removeKeys) {
            cacheMap.remove(key);
        }
        if (!removeKeys.isEmpty()) {
            log.info("Remove expired keys : " + removeKeys);
        }
        
    }
    
}
