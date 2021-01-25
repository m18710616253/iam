package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.entity.GroupUser;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.entity.UserGroup;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 将指定的用户添加到指定的组参数
 * @author wangduo
 *
 */
public class GroupUserParam extends ActionParameter {

    public String groupName;
    public String userName;
    
    /**
     * 参数校验
     */
    @Override
    public void validate() {
        // 校验用户名
       ValidationUtils.validateGroupName(groupName, errorMessages);
       // 验证用户名
       ValidationUtils.validateUserName(userName, errorMessages);
    }

    /**
     * 使用请求参数创建组下用户
     * @return
     */
    public GroupUser getGroupUser() {
        GroupUser groupUser = new GroupUser();
        groupUser.accountId = getAccountId();
        groupUser.groupName = groupName;
        groupUser.userName = userName;
        groupUser.joinDate = System.currentTimeMillis();
        return groupUser;
    }
    
    /**
     * 使用请求参数创建用户的
     * @return
     */
    public UserGroup getUserGroup() {
        UserGroup userGroup = new UserGroup();
        userGroup.accountId = getAccountId();
        userGroup.groupName = groupName;
        userGroup.userName = userName;
        return userGroup;
    }
    
    public Group getGroup() {
        Group group = new Group();
        group.accountId = getAccountId();
        group.groupName = groupName;
        return group;
    }
    
    public User getUser() {
        User user = new User();
        user.accountId = getAccountId();
        user.userName = userName;
        return user;
    }
    
    public String getResource() {
        return groupName;
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generateGroupArn(getAccountId(), groupName);
    }
    
    /**
     * 返回日志审计记录的ARN
     * @return
     */
    @Override
    public List<Resources> getTrailResources() {
        List<Resources> resources = new ArrayList<>();
        resources.add(ResourcesUtils.generateUserResources(getAccountId(), userName));
        resources.add(ResourcesUtils.generateGroupResources(getAccountId(), groupName));
        return resources;
    }
}
