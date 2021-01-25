package cn.ctyun.oos.iam.server.entity;

import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseTable;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.util.DateFormat;

/**
 * IAM子用户
 * @author wangduo
 */
@HBaseTable(name = "iam-user")
public class User extends HBaseEntity {

    // 列名
    public static final String QUALIFIER_USER_NAME = "userName";
    public static final String QUALIFIER_TAGS = "tags";
    public static final String QUALIFIER_ACCESSKEYS = "accessKeys";
    public static final String QUALIFIER_BUILTIN_AK = "builtInAk";
    public static final String QUALIFIER_MFA_NAME = "mFAName";
    public static final String QUALIFIER_GROUP_COUNT = "groupCount";
    public static final String QUALIFIER_POLICY_COUNT = "policyCount";
    
    @Qualifier
    public String userId;
    @Qualifier
    public String accountId;
    @Qualifier(name = QUALIFIER_USER_NAME)
    public String userName;
    @Qualifier
    public String password;
    @Qualifier
    @DateFormat
    public Long passwordCreateDate;
    @Qualifier
    public Boolean passwordResetRequired;
    @Qualifier
    public List<String> oldPasswords;
    /** 最后登录时间 */
    @Qualifier
    @DateFormat
    public Long passwordLastUsed;
    /** 最后登录IP */
    @Qualifier
    public String iPLastUsed;
    @Qualifier(name = QUALIFIER_TAGS)
    public List<Tag> tags;
    @Qualifier(name = QUALIFIER_ACCESSKEYS)
    public List<String> accessKeys;
    /** 用户内置AK，用于控制台访问时请求接口使用 */
    @Qualifier(name = QUALIFIER_BUILTIN_AK)
    public String builtInAccessKey;
    /** MFA名称 */
    @Qualifier(name = QUALIFIER_MFA_NAME)
    public String mFAName;
    /** 用户所属组的数量 */
    @Qualifier(name = QUALIFIER_GROUP_COUNT)
    public Long groupCount;
    /** 用户附加的策略数 */
    @Qualifier(name = QUALIFIER_POLICY_COUNT)
    public Long policyCount;
    /** 创建时间 */
    @Qualifier
    @DateFormat
    public Long createDate;
    
    public String arn;

    public String getArn() {
        return "arn:ctyun:iam::" + accountId + ":user/" + userName;
    }
    
    public String getRootArn() {
        return "arn:ctyun:iam::" + accountId + ":root";
    }

    @Override
    public byte[] getRowKey() {
        // userName判重不区分大小写
        return Bytes.toBytes(accountId + "|" + userName.toLowerCase());
    }

    /**
     * 缓存使用key
     * @return
     */
    public String getUserKey() {
        return accountId + "|" + userName;
    }
    
    /**
     * 解析缓存key
     * @param key
     */
    public void parseUserKey(String key) {
        String[] strs = key.split("\\|");
        accountId = strs[0];
        userName = strs[1];
    }
    
    /**
     * 验证密码是否过期
     * @param maxAge 过期时间，单位天
     * @return
     */
    public boolean passwordExpired(Integer maxAge) {
        // 没有过期时间
        if (maxAge == null || maxAge == 0) {
            return false;
        }
        // 如果用户没有密码
        if (StringUtils.isEmpty(password)) {
            return false;
        }
        // 没有创建时间
        if (passwordCreateDate == null || passwordCreateDate == 0) {
            return false;
        }
        // 判断密码是否在有效期内
        long expireTime = Long.valueOf(maxAge) * 24 * 60 * 60 * 1000L;
        return System.currentTimeMillis() - passwordCreateDate > expireTime;
    }
}
