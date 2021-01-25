package cn.ctyun.oos.iam.server.result;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.server.entity.Group;

/**
 * 组列表结果
 * 
 * @author wangduo
 *
 */
public class ListGroupsResult extends Result {

    public List<GroupResult> groups = new ArrayList<>();
    public boolean isTruncated = false;
    public String marker;
    public Long total;
    
    public ListGroupsResult(PageResult<Group> pageResult) {
        for (Group group : pageResult.list) {
        	GroupResult groupResult = new GroupResult();
            groupResult.groupName = group.groupName;
            groupResult.arn = group.getArn();
            groupResult.groupId = group.groupId;
            groupResult.createDate = group.createDate;
            groupResult.users = group.userCount == null ? 0 : group.userCount;
            groupResult.policies = group.policyCount == null ? 0 : group.policyCount;
            groups.add(groupResult);
        }
        this.isTruncated = pageResult.isTruncated;
        this.marker = pageResult.marker;
        this.total = pageResult.total;
    }
    
}
