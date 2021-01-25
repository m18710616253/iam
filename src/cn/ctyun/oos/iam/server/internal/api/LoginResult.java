package cn.ctyun.oos.iam.server.internal.api;

/**
 * 登录结果
 * @author wangduo
 *
 */
public class LoginResult {

    /** 密码过期 */
    public Boolean passwordExpired = false;
    /** 需要输入MFA验证码 */
    public Boolean mFACodeRequired = false;
    /** 是否需要用户重置密码 */
    public Boolean passwordResetRequired = false;
    /** 需要管理员重置密码 */
    public Boolean hardExpiry = false;
    /** 是否经过MFA认证 */
    public Boolean multiFactorAuthPresent = false;
    
    /** 账户ID */ 
    public String accountId;
    public String accessKeyId;
    public String secretAccessKey;
    public Long passwordLastUsed;
    public String iPLastUsed;
    
}
