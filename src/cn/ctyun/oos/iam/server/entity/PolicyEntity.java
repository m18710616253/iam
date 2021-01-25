package cn.ctyun.oos.iam.server.entity;

import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseTable;
import cn.ctyun.oos.iam.server.hbase.Qualifier;

/**
 * IAM策略附加到的实体
 * 实体包括用户和组
 * @author wangduo
 *
 */
@HBaseTable(entityClass = Policy.class)
public class PolicyEntity extends HBaseEntity {
    
    public static final String TYPE_USER = "User";
    public static final String TYPE_GROUP = "Group";
    
    @Qualifier
    public String accountId;
    @Qualifier
    /** 策略作用域 OOS, Local */
    public String scope;
    @Qualifier
    public String policyName;
    @Qualifier
    /** 实体类型 user, group */
    public String entityType;
    @Qualifier
    /** 实体名称 */
    public String entityName;
    /** 实体ID，用于展示 */
    @Qualifier
    public String id;
    
    public String getPolicyEntityPrefix() {
        return "entity|" + accountId + "|" + scope + "|" +  policyName.toLowerCase() + "|" + entityType + "|" ;
    }
    
    @Override
    public byte[] getRowKey() {
        return Bytes.toBytes(getPolicyEntityPrefix() + entityName.toLowerCase());
    }

}
