package cn.ctyun.oos.iam.server.entity;

import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseTable;
import cn.ctyun.oos.iam.server.hbase.Qualifier;

/**
 * IAM组被附加的策略
 * 用于组和策略的关系
 * @author wangduo
 *
 */
@HBaseTable(entityClass = Group.class)
public class GroupPolicy extends HBaseEntity {
    
    @Qualifier
    public String accountId;
    @Qualifier
    public String groupName;
    @Qualifier
    /** 策略作用域 系统策略：OOS，自定义策略：Local */
    public String scope;
    @Qualifier
    public String policyName;
    
    /**
     * 获取组和策略关系的前缀
     * 用于查询用户下的策略关系
     * @return
     */
    public String getGroupPolicyPrefix() {
        return "policy|" + accountId + "|" + groupName.toLowerCase()  + "|";
    }
    
    @Override
    public byte[] getRowKey() {
        return Bytes.toBytes(getGroupPolicyPrefix() + scope  + "|" +  policyName.toLowerCase());
    }

    public Policy getPolicy() {
        Policy policy = new Policy();
        policy.accountId = accountId;
        policy.scope = scope;
        policy.policyName = policyName;
        return policy;
    }
}
