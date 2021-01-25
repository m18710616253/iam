package cn.ctyun.oos.iam.server.cache;

import java.io.IOException;
import java.util.List;
import java.util.Timer;

import cn.ctyun.oos.iam.accesscontroller.cache.IAMSingleUpdateCache;
import cn.ctyun.oos.iam.server.service.AttachedPolicyService;

/**
 * 附加到用户的策略列表的缓存
 * key：userKey
 * value : policyKey列表
 * @author wangduo
 *
 */
public class AttachUserPolicyKeysCache extends IAMSingleUpdateCache {

    public AttachUserPolicyKeysCache(Timer timer) {
        super(timer);
    }

    /**
     * 获取附加在用户上的策略的key列表
     * key：userKey
     * value : policyKey列表
     */
    @Override
    public Object load(Object key) throws IOException {
        return AttachedPolicyService.getAttachedUserPolicyKeys(key.toString());
    }

    /**
     * 获取缓存中数据，没有数据使用load进行加载，加载后放入缓存
     * @param userKey
     * @return
     * @throws IOException
     */
    @SuppressWarnings("unchecked")
    public List<String> getPolicyKeys(String userKey) throws IOException {
        return (List<String>) get(userKey);
    }
    
}
