package cn.ctyun.oos.iam.server.result;

import cn.ctyun.oos.iam.server.util.DateFormat;

/**
 * 用户登录配置
 * @author wangduo
 *
 */
public class LoginProfile {

    public String userName;
    public Boolean passwordResetRequired;
    @DateFormat
    public Long createDate;

}
