package cn.ctyun.oos.iam.server.cache;

import java.io.IOException;
import java.util.List;
import java.util.Timer;

import cn.ctyun.oos.iam.accesscontroller.cache.IAMSingleUpdateCache;
import cn.ctyun.oos.iam.server.service.AttachedPolicyService;

/**
 * 用户的组列表的缓存
 * key：userKey
 * value : groupKey列表
 * @author wangduo
 *
 */
public class UserGroupKeysCache extends IAMSingleUpdateCache {

    public UserGroupKeysCache(Timer timer) {
        super(timer);
    }

    /**
     * 获取附加在组上的策略的key列表
     * key：userKey
     * value : groupKey列表
     */
    @Override
    public Object load(Object key) throws IOException {
        return AttachedPolicyService.getUserGroupKeys(key.toString());
    }

    /**
     * 获取缓存中数据，没有数据使用load进行加载，加载后放入缓存
     * @param userKey
     * @return
     * @throws IOException
     */
    @SuppressWarnings("unchecked")
    public List<String> getGroupKeys(String userKey) throws IOException {
        return (List<String>) get(userKey);
    }
    
}
