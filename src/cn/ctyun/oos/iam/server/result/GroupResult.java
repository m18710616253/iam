package cn.ctyun.oos.iam.server.result;

import cn.ctyun.oos.iam.server.util.DateFormat;

/**
 * listGroup的响应结果
 * @author wangduo
 *
 */
public class GroupResult extends Result {
    
    public String groupId;
    public String groupName;
    /** 创建时间 */
    @DateFormat
    public Long createDate;
    /** 组下用户数 */
    public Long users;
    /** 组附加的策略数 */
    public Long policies;
    
    public String arn;
}
