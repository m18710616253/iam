package cn.ctyun.oos.iam.server.entity;

import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseTable;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.param.PolicyScopeType;

/**
 * IAM策略附加计数
 * 记录IAM策略附加到的实体（用户，组）的数量
 * @author wangduo
 *
 */
@HBaseTable(entityClass = Policy.class)
public class PolicyAttachmentCount extends HBaseEntity {
    
    public static final String QUALIFIER_COUNT = "count";
    
    @Qualifier
    public String accountId;
    @Qualifier
    public String policyName;
    @Qualifier
    /** 策略作用域 系统策略：OOS，自定义策略：Local */
    public String scope;
    /** 附加计数 */
    @Qualifier(name = QUALIFIER_COUNT)
    public Long count;
    
    public PolicyAttachmentCount() {}
    
    public PolicyAttachmentCount(Policy policy, String accountId) {
        this.accountId = accountId;
        this.policyName = policy.policyName;
        this.scope = policy.scope;
    }

    @Override
    public byte[] getRowKey() {
        return Bytes.toBytes("count|" + accountId + "|" + scope  + "|" +  policyName.toLowerCase());
    }
    
    public Policy getPolicy() {
        Policy policy = new Policy();
        policy.accountId = accountId;
        if (PolicyScopeType.OOS.value.equals(scope)) {
        	policy.accountId = scope;
        }
        policy.scope = scope;
        policy.policyName = policyName;
        return policy;
    }

	@Override
	public String toString() {
		return "[accountId=" + accountId + ", policyName=" + policyName + ", scope=" + scope + ", count=" + count + "]";
	}
}
