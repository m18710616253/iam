package cn.ctyun.oos.iam.server.entity;

import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseTable;
import cn.ctyun.oos.iam.server.hbase.Qualifier;

/**
 * 账户密码策略
 * 
 * @author wangduo
 *
 */
@HBaseTable(name = "iam-passwordPolicy")
public class AccountPasswordPolicy extends HBaseEntity {

    /** 账户ID */
    @Qualifier
    public String accountId;
    /** 是否允许用户更改其密码 */
    @Qualifier
    public Boolean allowUsersToChangePassword;
    /** 密码过期需要管理员重置 */
    @Qualifier
    public Boolean hardExpiry;
    /** 密码有效期（天）1-1095 */
    @Qualifier
    public Integer maxPasswordAge;
    /** 密码最小长度 6-128 */
    @Qualifier
    public Integer minimumPasswordLength;
    /** 防止密码重复使用，记录密码个数 1-24，0代表可以重复 */
    @Qualifier
    public Integer passwordReusePrevention;
    /** 至少需要一个小写字母 */
    @Qualifier
    public Boolean requireLowercaseCharacters;
    /** 至少需要一个数字 */
    @Qualifier
    public Boolean requireNumbers;
    /** 至少需要一个非字母数字字符 */
    @Qualifier
    public Boolean requireSymbols;
    /** 至少需要一个大写字母 */
    @Qualifier
    public Boolean requireUppercaseCharacters;

    /** 指示帐户中的密码是否会过期 */
    public Boolean expirePasswords;
    
    @Override
    public byte[] getRowKey() {
        return Bytes.toBytes(accountId);
    }
    
}
