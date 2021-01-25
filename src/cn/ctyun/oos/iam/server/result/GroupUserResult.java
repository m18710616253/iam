package cn.ctyun.oos.iam.server.result;

import cn.ctyun.oos.iam.server.util.DateFormat;

/**
 * 组下用户响应结果
 * @author wangduo
 *
 */
public class GroupUserResult extends Result {
    
    public String userId;
    public String path;
    public String userName;
    public String arn;
    @DateFormat
    public Long passwordLastUsed;
    @DateFormat
    public Long joinDate;
    @DateFormat
    public Long createDate;
}
