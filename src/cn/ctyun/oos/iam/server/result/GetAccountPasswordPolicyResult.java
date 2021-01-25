package cn.ctyun.oos.iam.server.result;

import cn.ctyun.oos.iam.server.entity.AccountPasswordPolicy;

/**
 * 账户的密码策略
 * @author wangduo
 *
 */
public class GetAccountPasswordPolicyResult extends Result {

    public AccountPasswordPolicy passwordPolicy;

    public GetAccountPasswordPolicyResult(AccountPasswordPolicy passwordPolicy) {
        // 不返回账户ID
        passwordPolicy.accountId = null;
        this.passwordPolicy = passwordPolicy;
    }
    
}
