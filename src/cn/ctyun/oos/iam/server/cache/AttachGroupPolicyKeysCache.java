package cn.ctyun.oos.iam.server.cache;

import java.io.IOException;
import java.util.List;
import java.util.Timer;

import cn.ctyun.oos.iam.accesscontroller.cache.IAMSingleUpdateCache;
import cn.ctyun.oos.iam.server.service.AttachedPolicyService;

/**
 * 附加到组的策略列表的缓存
 * key：groupKey
 * value : policyKey列表
 * @author wangduo
 *
 */
public class AttachGroupPolicyKeysCache extends IAMSingleUpdateCache {

    public AttachGroupPolicyKeysCache(Timer timer) {
        super(timer);
    }

    /**
     * 获取附加在组上的策略的key列表
     * key：groupKey
     * value : policyKey列表
     */
    @Override
    public Object load(Object key) throws IOException {
        return AttachedPolicyService.getAttachedGroupPolicyKeys(key.toString());
    }

    /**
     * 获取缓存中数据，没有数据使用load进行加载，加载后放入缓存
     * @param userKey
     * @return
     * @throws IOException
     */
    @SuppressWarnings("unchecked")
    public List<String> getPolicyKeys(String groupKey) throws IOException {
        return (List<String>) get(groupKey);
    }
    
}
