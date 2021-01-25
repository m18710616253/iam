package cn.ctyun.oos.iam.server.action.api;

import java.io.IOException;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.iam.accesscontroller.util.ExceptionUtils;
import cn.ctyun.oos.iam.server.action.Action;
import cn.ctyun.oos.iam.server.entity.AccountPasswordPolicy;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.param.DeleteAccountPasswordPolicyParam;
import cn.ctyun.oos.iam.server.param.GetAccountPasswordPolicyParam;
import cn.ctyun.oos.iam.server.param.UpdateAccountPasswordPolicyParam;
import cn.ctyun.oos.iam.server.result.GetAccountPasswordPolicyResult;
import cn.ctyun.oos.iam.server.service.AccountPasswordPolicyService;

/**
 * 账号密码策略相关接口
 * @author wangduo
 *
 */
@Action
public class AccountPasswordPolicyAction {
    
    /**
     * 获取账户的密码策略
     * @param param
     * @return
     * @throws IOException 
     * @throws BaseException 
     */
    public static GetAccountPasswordPolicyResult getAccountPasswordPolicy(GetAccountPasswordPolicyParam param) throws IOException {
        AccountPasswordPolicy passwordPolicy = AccountPasswordPolicyService.getAccountPasswordPolicy(param.getAccountId());
        passwordPolicy.expirePasswords = (passwordPolicy.maxPasswordAge != null && passwordPolicy.maxPasswordAge > 0);
        GetAccountPasswordPolicyResult result = new GetAccountPasswordPolicyResult(passwordPolicy);
        return result;
    }
    
    /**
     * 更新账户的密码策略
     * 没有传入的参数会使用默认值进行更新
     * @param param
     * @throws IOException 
     */
    public static void updateAccountPasswordPolicy(UpdateAccountPasswordPolicyParam param) throws IOException {
        
        AccountPasswordPolicy accountPasswordPolicy = AccountPasswordPolicyService.getAccountPasswordPolicy(param.getAccountId());
        
        if (param.allowUsersToChangePassword != null) {
            accountPasswordPolicy.allowUsersToChangePassword = param.allowUsersToChangePassword;
        }
        if (param.hardExpiry != null) {
            accountPasswordPolicy.hardExpiry = param.hardExpiry;
        }
        if (param.maxPasswordAge != null) {
            accountPasswordPolicy.maxPasswordAge = param.maxPasswordAge;
        }
        if (param.minimumPasswordLength != null) {
            accountPasswordPolicy.minimumPasswordLength = param.minimumPasswordLength;
        }
        if (param.passwordReusePrevention != null) {
            accountPasswordPolicy.passwordReusePrevention = param.passwordReusePrevention;
        }
        if (param.requireLowercaseCharacters != null) {
            accountPasswordPolicy.requireLowercaseCharacters = param.requireLowercaseCharacters;
        }
        if (param.requireNumbers != null) {
            accountPasswordPolicy.requireNumbers = param.requireNumbers;
        }
        if (param.requireSymbols != null) {
            accountPasswordPolicy.requireSymbols = param.requireSymbols;
        }
        if (param.requireUppercaseCharacters != null) {
            accountPasswordPolicy.requireUppercaseCharacters = param.requireUppercaseCharacters;
        }
        HBaseUtils.put(accountPasswordPolicy);
    }
    
    /**
     * 删除账户的密码策略
     * @param param
     * @throws IOException 
     * @throws BaseException 
     */
    public static void deleteAccountPasswordPolicy(DeleteAccountPasswordPolicyParam param) throws IOException, BaseException {
        AccountPasswordPolicy passwordPolicy = new AccountPasswordPolicy();
        passwordPolicy.accountId = param.getAccountId();
        // 获取账户的密码策略
        if (!HBaseUtils.exist(passwordPolicy)) {
            throw ExceptionUtils.newNoSuchAccountPasswordPolicyException(param.getAccountId());
        }
        HBaseUtils.delete(passwordPolicy);
    }
}
