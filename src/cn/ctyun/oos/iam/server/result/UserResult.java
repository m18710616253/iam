package cn.ctyun.oos.iam.server.result;

import cn.ctyun.oos.iam.server.util.DateFormat;

/**
 * ListUsers返回结果
 * @author wangduo
 *
 */
public class UserResult extends Result {

    public String userId;
    public String arn;
    public String userName;
    /** 密码的创建时间 */
    @DateFormat
    public Long passwordCreateDate;
    /** 用户密码最后使用时间 */
    @DateFormat
    public Long passwordLastUsed;
    /** 用户的AK数量 */
    public Integer accessKeyCount;
    /** 用户关联的MFA数量 */
    public Integer mFADeviceCount;
    /** 创建用户时的日期和时间 */
    @DateFormat
    public Long createDate;
}
