package cn.ctyun.oos.iam.server.entity;

import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseTable;
import cn.ctyun.oos.iam.server.hbase.Qualifier;

/**
 * IAM用户被附加的策略
 * 用于用户和策略的关系
 * @author wangduo
 *
 */
@HBaseTable(entityClass = User.class)
public class UserPolicy extends HBaseEntity {
    
    @Qualifier
    public String accountId;
    @Qualifier
    public String userName;
    /** 策略作用域 系统策略：OOS，自定义策略：Local */
    @Qualifier
    public String scope;
    @Qualifier
    public String policyName;
    
    /**
     * 获取用户和策略关系的前缀
     * 用于查询用户下的策略关系
     * @return
     */
    public String getUserPolicyPrefix() {
        return "policy|" + accountId + "|" + userName.toLowerCase()  + "|";
    }
    
    @Override
    public byte[] getRowKey() {
        return Bytes.toBytes(getUserPolicyPrefix() + scope  + "|" +  policyName.toLowerCase());
    }
    
    public Policy getPolicy() {
        Policy policy = new Policy();
        policy.accountId = accountId;
        policy.scope = scope;
        policy.policyName = policyName;
        return policy;
    }
}
