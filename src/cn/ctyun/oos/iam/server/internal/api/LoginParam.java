package cn.ctyun.oos.iam.server.internal.api;

import cn.ctyun.oos.iam.server.entity.User;

/**
 * 登录参数
 * @author wangduo
 *
 */
public class LoginParam {

    /** 账户ID */
    public String accountId;
    /** 用户名 */
    public String userName;
    /** 密码的MD5 */
    public String passwordMd5;
    /** MFA验证码 */
    public Long mFACode;
    /** 登录IP */
    public String loginIp;
    
    
    public User getUser() {
        User user = new User();
        user.accountId = accountId;
        user.userName = userName;
        return user;
    }
}
