package cn.ctyun.oos.iam.server.result;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.entity.GroupUser;
import cn.ctyun.oos.iam.server.entity.User;

/**
 * GetGroup返回结果
 * @author wangduo
 *
 */
public class GetGroupResult extends Result {

    public Group group = new Group();
    public List<GroupUserResult> users = new ArrayList<>();
    public boolean isTruncated = false;
    public String marker;
    
    public GetGroupResult(Group group, List<User> usersResult, PageResult<GroupUser> groupUsersResult) {
        
        // 只返回需要展示的数据
        this.group.groupName = group.groupName;
        this.group.groupId = group.groupId;
        this.group.createDate = group.createDate;
        this.group.arn = group.getArn();
        
        Map<String, Long> userJoinDateMap = new HashMap<>();
        for (GroupUser groupUser : groupUsersResult.list) {
            userJoinDateMap.put(groupUser.userName, groupUser.joinDate);
        }
        
        for (User user : usersResult) {
            GroupUserResult userResult = new GroupUserResult();
            userResult.userName = user.userName;
            userResult.userId = user.userId;
            userResult.arn = user.getArn();
            userResult.passwordLastUsed = user.passwordLastUsed;
            userResult.joinDate = userJoinDateMap.get(userResult.userName);
            userResult.createDate = user.createDate;
            users.add(userResult);
        }
        
        this.isTruncated = groupUsersResult.isTruncated;
        this.marker = groupUsersResult.marker;
    }
}
