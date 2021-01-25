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
public class ListGroupsForUserResult extends Result {

    public List<Group> groups = new ArrayList<>();
    public boolean isTruncated = false;
    public String marker;
    public Long total;
    
    public ListGroupsForUserResult(PageResult<Group> pageResult) {
        for (Group group : pageResult.list) {
            Group groupResult = new Group();
            groupResult.groupName = group.groupName;
            groupResult.arn = group.getArn();
            groupResult.groupId = group.groupId;
            groupResult.createDate = group.createDate;
            groups.add(groupResult);
        }
        this.isTruncated = pageResult.isTruncated;
        this.marker = pageResult.marker;
        this.total = pageResult.total;
    }
    
}
