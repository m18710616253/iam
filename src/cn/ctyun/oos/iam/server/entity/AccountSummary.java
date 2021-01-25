package cn.ctyun.oos.iam.server.entity;

import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseTable;
import cn.ctyun.oos.iam.server.hbase.Qualifier;

/**
 * IAM的实体使用和配额信息
 * 
 * @author wangduo
 *
 */
@HBaseTable(name = "iam-accountSummary")
public class AccountSummary extends HBaseEntity {

    // 列名 
    public static final String ACCOUNT_ID = "accountId";
    public static final String USERS = "users";
    public static final String GROUPS = "groups";
    public static final String POLICIES = "policies";
    public static final String MFA_DEVICES = "mFADevices";
    public static final String MFA_DEVICES_IN_USE = "mFADevicesInUse";
    public static final String ACCOUNT_MFA_ENABLED = "accountMFAEnabled";
    public static final String USERS_QUOTA = "usersQuota";
    public static final String GROUPS_QUOTA = "groupsQuota";
    public static final String POLICIES_QUOTA = "policiesQuota";
    public static final String GROUPS_PER_USER_QUOTA = "groupsPerUserQuota";
    public static final String ATTACHED_POLICIES_PER_USER_QUOTA = "attachedPoliciesPerUserQuota";
    public static final String ATTACHED_POLICIES_PER_GROUP_QUOTA = "attachedPoliciesPerGroupQuota";
    public static final String ACCESSKEYS_PER_USER_QUOTA = "accessKeysPerUserQuota";
    public static final String ACCESSKEYS_PER_ACCOUNT_QUOTA = "accessKeysRootUserQuota";
    /** 系统限额rowkey */
    public static final String SYSTEM_ROWKEY = "systemQuota";
    
    // 账户计数部分
    /** 账户ID */
    @Qualifier(name = ACCOUNT_ID)
    public String accountId;
    /** 账号已有的用户总数 */
    @Qualifier(name = USERS)
    public Long users;
    /** 账号已有的用户组的总数 */
    @Qualifier(name = GROUPS)
    public Long groups;
    /** 账号已有的策略总数 */
    @Qualifier(name = POLICIES)
    public Long policies;
    /** 账号中已有的MFA设备总数 */
    @Qualifier(name = MFA_DEVICES)
    public Long mFADevices;
    /** 在使用的MFA设备总数，账户中用户启用的MFA总数 */
    @Qualifier(name = MFA_DEVICES_IN_USE)
    public Long mFADevicesInUse;
    /** 账号（根用户）启用MFA的数量（最大为1） */
    @Qualifier(name = ACCOUNT_MFA_ENABLED)
    public Long accountMFAEnabled;
    /** 根用户的已有AccessKey数量 */
    public Long accountAccessKeysPresent;
    
    // 账户限额部分
    /** 用户数量限制 */
    @Qualifier(name = USERS_QUOTA)
    public Long usersQuota;
    /** 用户组数量限制 */
    @Qualifier(name = GROUPS_QUOTA)
    public Long groupsQuota;
    /** 策略数量限制 */
    @Qualifier(name = POLICIES_QUOTA)
    public Long policiesQuota;
    /** 每个用户加入的组的数量限制 */
    @Qualifier(name = GROUPS_PER_USER_QUOTA)
    public Long groupsPerUserQuota;
    /** 每个用户的附加策略数量限制 */
    @Qualifier(name = ATTACHED_POLICIES_PER_USER_QUOTA)
    public Long attachedPoliciesPerUserQuota;
    /** 每个组的附加策略数量限制 */
    @Qualifier(name = ATTACHED_POLICIES_PER_GROUP_QUOTA)
    public Long attachedPoliciesPerGroupQuota;
    /** 每个子用户的AccessKey数量限制 */
    @Qualifier(name = ACCESSKEYS_PER_USER_QUOTA)
    public Long accessKeysPerUserQuota;
    /** 根用户的AccessKey数量限制 */
    @Qualifier(name = ACCESSKEYS_PER_ACCOUNT_QUOTA)
    public Long accessKeysPerAccountQuota;
    
    @Override
    public byte[] getRowKey() {
        return Bytes.toBytes(accountId);
    }
    
    public static String getSystemRowKey() {
        return SYSTEM_ROWKEY;
    }

}
