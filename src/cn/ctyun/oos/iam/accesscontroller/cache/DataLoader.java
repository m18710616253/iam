package cn.ctyun.oos.iam.accesscontroller.cache;

import java.io.IOException;

/**
 * 数据加载类
 * 用于在缓存中读取不到数据的情况下, 限制并发访问数据库
 * @author wangduo
 *
 */
public interface DataLoader<T> {

    /**
     * 获取数据
     * @param key
     * @return
     * @throws IOException 
     */
    T get(String key) throws IOException;
    
    /**
     * 缓存中是否包含该数据
     * @param key
     * @return
     */
    boolean contains(String key);
    
    /**
     * 从数据库加载数据，并存放到缓存
     * @param key
     * @return
     * @throws IOException
     */
    T loadAndSet(String key) throws IOException;
    
    /**
     * 从缓存加载数据
     * @param key
     * @return
     * @throws IOException 
     */
    T fromCache(String key) throws IOException;
}
