package cn.ctyun.oos.iam.server.entity;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseTable;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.param.PolicyScopeType;
import cn.ctyun.oos.iam.server.util.DateFormat;
import cn.ctyun.oos.iam.server.util.TrailDate;

/**
 * IAM权限策略
 * 
 * @author wangduo
 */
@HBaseTable(name = "iam-policy")
public class Policy extends HBaseEntity {

    // 列名
    public static final String QUALIFIER_POLICY_NAME = "policyName";
    public static final String QUALIFIER_DOCUMENT = "document";
    public static final String QUALIFIER_ATTACHED_TOTAL = "attachedTotal";
    
    @Qualifier
    public String policyId;
    @Qualifier
    public String accountId;
    @Qualifier(name = QUALIFIER_POLICY_NAME)
    public String policyName;
    /** 策略作用范围，OOS:系统策略 Local:用户自定义策略 */
    @Qualifier
    public String scope;
    @Qualifier(name = QUALIFIER_DOCUMENT)
    public String document;
    @Qualifier
    public String description;
    /** 创建时间 */
    @Qualifier
    @DateFormat
    @TrailDate
    public Long createDate;
    @Qualifier
    @DateFormat
    @TrailDate
    public Long updateDate;
    @Qualifier
    public Boolean isAttachable;
    /** 系统策略使用字段，一共被附加了多少次 */
    @Qualifier
    public Long attachedTotal;
    
    public Long attachmentCount;
    
    public String arn;
    
    public String getArn() {
        String scopeType = PolicyScopeType.OOS.value.equalsIgnoreCase(scope) ? PolicyScopeType.OOS.value : accountId;
        return "arn:ctyun:iam::" + scopeType + ":policy/" + policyName;
    }    

    /**
     * 解析策略的ARN，并赋值到策略
     * @param arn
     * @throws ParseArnException
     */
    public void parseArn(String arn) throws ParseArnException {
        if (arn == null) {
            throw new ParseArnException();
        }
        // 不区分大小写，转小写
        arn = arn.toLowerCase();
        // 前缀不对
        if (!arn.startsWith("arn:ctyun:iam::") && !arn.startsWith("arn:aws:iam::")) {
            throw new ParseArnException();
        }
        String[] arnStrs = arn.split(":");
        if (arnStrs.length != 6) {
            throw new ParseArnException();
        }
        // 如果没有填账户ID部分
        if (StringUtils.isEmpty(arnStrs[4])) {
            throw new ParseArnException();
        }
        if (PolicyScopeType.OOS.value.equalsIgnoreCase(arnStrs[4]) || "aws".equalsIgnoreCase(arnStrs[4])) {
            scope = PolicyScopeType.OOS.value;
        } else {
            scope = PolicyScopeType.Local.value;
        }
        // 获取ARN账号部分
        accountId = arnStrs[4];
        
        // 获取策略路径和名称部分
        String pathPolicy = arnStrs[5];
        // 没有以policy开头
        if (!pathPolicy.startsWith("policy/")) {
            throw new ParseArnException();
        }
        String[] strs = pathPolicy.split("/");
        policyName = strs[strs.length -1];
    }   
    
    public String getPolicyKey() {
        // 系统策略key
        if (PolicyScopeType.OOS.value.equalsIgnoreCase(scope)) {
            return PolicyScopeType.OOS.value + "|" + policyName.toLowerCase();
        }
        return accountId + "|" + policyName.toLowerCase();
    }
    
    @Override
    public byte[] getRowKey() {
        return Bytes.toBytes(getPolicyKey());
    }

    public byte[] getAttachmentCountRowKey(String attachedAccountId) {
        return Bytes.toBytes("count|" + attachedAccountId + "|" + scope + "|" + policyName.toLowerCase());
    }
    
}
