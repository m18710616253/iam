package cn.ctyun.oos.iam.server.service;

import java.io.IOException;

import cn.ctyun.oos.iam.server.entity.AccountPasswordPolicy;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;

/**
 * 账户密码策略通用逻辑
 * @author wangduo
 *
 */
public class AccountPasswordPolicyService {

    /**
     * 获取账户密码策略
     * @return
     * @throws IOException 
     */
    public static AccountPasswordPolicy getAccountPasswordPolicy(String accountId) throws IOException {
        
        AccountPasswordPolicy passwordPolicy = new AccountPasswordPolicy();
        passwordPolicy.accountId = accountId;
        passwordPolicy = HBaseUtils.get(passwordPolicy);
        if (passwordPolicy == null) {
            // 返回默认值
            return getDefaultAccountPasswordPolicy(accountId);
        } else {
            // 返回已设置的密码策略
            return passwordPolicy;
        }
    }
    
    /**
     * 获取默认的账户密码策略
     * @return
     */
    private static AccountPasswordPolicy getDefaultAccountPasswordPolicy(String accountId) {
        AccountPasswordPolicy accountPasswordPolicy = new AccountPasswordPolicy();
        accountPasswordPolicy.accountId = accountId;
        accountPasswordPolicy.allowUsersToChangePassword = true;
        accountPasswordPolicy.hardExpiry = false;
        accountPasswordPolicy.maxPasswordAge = 0;
        accountPasswordPolicy.minimumPasswordLength = 8;
        accountPasswordPolicy.passwordReusePrevention = 0;
        accountPasswordPolicy.requireLowercaseCharacters = true;
        accountPasswordPolicy.requireNumbers = true;
        accountPasswordPolicy.requireSymbols = false;
        accountPasswordPolicy.requireUppercaseCharacters = false;
        accountPasswordPolicy.expirePasswords = false;
        return accountPasswordPolicy;
    }
    
}
