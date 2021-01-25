package cn.ctyun.oos.iam.server.entity;

import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseTable;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.util.DateFormat;
import cn.ctyun.oos.iam.server.util.TrailDate;

/**
 * IAM组
 * @author wangduo
 *
 */
@HBaseTable(name = "iam-group")
public class Group extends HBaseEntity {
    
    // 列名
    public static final String QUALIFIER_GROUP_NAME = "groupName";
    public static final String QUALIFIER_USER_COUNT = "userCount";
    public static final String QUALIFIER_POLICY_COUNT = "policyCount";
    
    @Qualifier
    public String groupId;
    @Qualifier(name = QUALIFIER_GROUP_NAME)
    public String groupName;
    @Qualifier
    public String accountId;
    /** 创建时间 */
    @Qualifier
    @DateFormat
    @TrailDate
    public Long createDate;
    /** 组下用户数 */
    @Qualifier(name = QUALIFIER_USER_COUNT)
    public Long userCount;
    /** 组附加的策略数 */
    @Qualifier(name = QUALIFIER_POLICY_COUNT)
    public Long policyCount;
    
    public String arn;
    
    public String getArn() {
        return "arn:ctyun:iam::" + accountId + ":group/" + groupName;
    }

    /**
     * 组缓存key
     * @return
     */
    public String getGroupKey() {
        return accountId + "|" + groupName.toLowerCase();
    }
    
    /**
     * 解析组key
     * @param key
     */
    public void parseGroupKey(String key) {
        String[] strs = key.split("\\|");
        accountId = strs[0];
        groupName = strs[1];
    }
    
    @Override
    public byte[] getRowKey() {
        // groupName判重不区分大小写
        return Bytes.toBytes(accountId + "|" + groupName.toLowerCase());
    }

}
