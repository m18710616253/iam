package cn.ctyun.oos.iam.server.action.api;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.filter.CompareFilter.CompareOp;
import org.apache.hadoop.hbase.filter.FilterList;
import org.apache.hadoop.hbase.filter.SingleColumnValueFilter;
import org.apache.hadoop.hbase.filter.SubstringComparator;
import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.util.ExceptionUtils;
import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;
import cn.ctyun.oos.iam.accesscontroller.util.IAMException;
import cn.ctyun.oos.iam.server.action.Action;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.entity.GroupUser;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.entity.UserGroup;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.param.CreateGroupParam;
import cn.ctyun.oos.iam.server.param.DeleteGroupParam;
import cn.ctyun.oos.iam.server.param.GetGroupParam;
import cn.ctyun.oos.iam.server.param.GroupUserParam;
import cn.ctyun.oos.iam.server.param.ListGroupsForUserParam;
import cn.ctyun.oos.iam.server.param.ListGroupsParam;
import cn.ctyun.oos.iam.server.result.CreateGroupResult;
import cn.ctyun.oos.iam.server.result.GetGroupResult;
import cn.ctyun.oos.iam.server.result.ListGroupsForUserResult;
import cn.ctyun.oos.iam.server.result.ListGroupsResult;
import cn.ctyun.oos.iam.server.result.PageResult;
import cn.ctyun.oos.iam.server.service.AccountSummaryService;
import cn.ctyun.oos.iam.server.service.GroupService;
import cn.ctyun.oos.metadata.IamChangeEvent;
import cn.ctyun.oos.metadata.IamChangeEvent.ChangeType;

/**
 * 用户组接口
 * @author wangduo
 *
 */
@Action
public class GroupAction {
    
    private static MetaClient client = MetaClient.getGlobalClient();
    
    /**
     * 创建组
     * @param param
     * @return
     * @throws Exception 
     */
    public static CreateGroupResult createGroup(CreateGroupParam param) throws Exception {
        Group group = param.getGroup();
        
        // 获取当前账户的使用及配额信息，对组数量和组配额进行判断
        AccountSummary accountSummary = AccountSummaryService.getAccountSummary(param.getAccountId());
        if (accountSummary.groups >= accountSummary.groupsQuota) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("groupsQuota", 
                    "Cannot exceed quota for GroupsPerAccount: %s.", accountSummary.groupsQuota);
            throw new IAMException(409, "LimitExceeded", errorMessage);
        }
        
        // 组名已存在
        boolean created = HBaseUtils.checkAndCreate(group);
        if (created) {
            // 账户下组数量加1
            AccountSummaryService.increment(param.getAccountId(), AccountSummary.GROUPS, 1);
        } else {
            IAMErrorMessage errorMessage = new IAMErrorMessage("groupAlreadyExists", "Group with name %s already exists.", group.groupName);
            throw new IAMException(409, "EntityAlreadyExists", errorMessage);
        }
        return new CreateGroupResult(group);
    }
    
    /**
     * 删除指定的IAM组
     * http://localhost:9097/?Action=DeleteGroup&GroupName=testGroup
     * @param param
     * @throws Throwable 
     */
    public static void deleteGroup(DeleteGroupParam param) throws Throwable {
        
        Group group = param.getGroup();
        group = HBaseUtils.get(group);
        if (group == null) {
            throw ExceptionUtils.newNoSuchGroupException(param.groupName);
        }
        // 如果请求来自于控制台
        if (param.isFromConsole) {
            // 删除组关系数据
            GroupService.deleteGroupAttached(group, param);
        } else {
            // 该组不得包含任何用户或具有任何附加策略
            deleteConflictCheck(group, param);
        }
        boolean deleted = HBaseUtils.checkAndDelete(group);
        if (deleted) {
            // 账户下组数量减1
            AccountSummaryService.increment(param.getAccountId(), AccountSummary.GROUPS, -1);
        }
    }
    
    /**
     * 组删除校验
     * 控制台访问时，将所有错误收集后进行返回
     * @param user
     * @param param
     * @return
     * @throws IOException
     * @throws BaseException
     */
    private static void deleteConflictCheck(Group group, DeleteGroupParam param) throws IOException, BaseException {
        IAMErrorMessage userError = new IAMErrorMessage("groupHasUser", "Cannot delete entity, must remove users from group first.", param.groupName);
        IAMErrorMessage policyError = new IAMErrorMessage("groupHasPolicy", "Cannot delete entity, must detach all policies first.", param.groupName);
        // 组不能包含用户
        if (group.userCount != null && group.userCount > 0) {
            throw new IAMException(409, "DeleteConflict", userError);
        }
        // 组不能附加策略
        if (group.policyCount != null &&  group.policyCount > 0) {
            throw new IAMException(409, "DeleteConflict", policyError);
        }
    }
    
    
    /**
     * 返回指定组下的用户列表
     * http://localhost:9097/?Action=GetGroup&GroupName=testGroup
     * @param param
     * @return
     * @throws Throwable 
     */
    public static GetGroupResult getGroup(GetGroupParam param) throws Throwable {
        Group group = HBaseUtils.get(param.getGroupParam());
        // 没有找到组
        if (group == null) {
            throw ExceptionUtils.newNoSuchGroupException(param.groupName);
        }
        // 组下用户关系查询
        GroupUser groupUserQuery = new GroupUser();
        groupUserQuery.accountId = group.accountId;
        groupUserQuery.groupName = group.groupName;
        // 通过用户组关系分页获取UserName 
        Scan scan = HBaseUtils.buildScan(groupUserQuery.getGroupPrefix(), param.marker);
        PageResult<GroupUser> groupUserPageResult = HBaseUtils.scan(scan, param.maxItems, GroupUser.class);
        List<byte[]> userRowKeys = new ArrayList<>();
        for (GroupUser groupUser : groupUserPageResult.list) {
            userRowKeys.add(groupUser.getUser().getRowKey());
        }
        // 批量获取用户数据
        List<User> users = HBaseUtils.get(userRowKeys, User.class);
        return new GetGroupResult(group, users, groupUserPageResult);
    }
    
    /**
     * 获取账户下的组列表
     * http://localhost:9097/?Action=ListGroups
     * @param param
     * @return
     * @throws Throwable 
     */
    public static ListGroupsResult listGroups(ListGroupsParam param) throws Throwable {
        Scan scan = HBaseUtils.buildScan(param.getAccountId(), param.marker);
        FilterList filterList = new FilterList();
        // 组名模糊匹配
        if (param.groupName != null) {
            SingleColumnValueFilter filter = new SingleColumnValueFilter(Bytes.toBytes(Qualifier.DEFAULT_FAMILY), Bytes.toBytes(Group.QUALIFIER_GROUP_NAME), 
                    CompareOp.EQUAL, new SubstringComparator(param.groupName));
            filterList.addFilter(filter);
        }
        if (filterList.getFilters().size() > 0) {
            scan.setFilter(filterList);
        }
        // 当marker为空，并且请求来自于proxy时获取数据总数
        boolean getTotal = param.marker == null && param.isFromConsole;
        PageResult<Group> pageResult = HBaseUtils.scan(scan, param.maxItems, Group.class, getTotal);
        return new ListGroupsResult(pageResult);
    }
    
    /**
     * 将指定的用户添加到指定的组
     * http://localhost:9097/?Action=AddUserToGroup&GroupName=testGroup&UserName=testUser
     * @param param
     * @throws Exception 
     */
    public static void addUserToGroup(GroupUserParam param) throws Exception {
        
        Group group = HBaseUtils.get(param.getGroup());
        // 没有找到组
        if (group == null) {
            throw ExceptionUtils.newNoSuchGroupException(param.groupName);
        }
        User user = HBaseUtils.get(param.getUser());
        // 没有找到用户
        if (user == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        
        // 获取当前账户的使用及配额信息
        AccountSummary accountSummary = AccountSummaryService.getAccountSummary(param.getAccountId());
        // 用户的组数量加1
        long userGroupCount = HBaseUtils.incrementColumnValue(user, Bytes.toBytes(User.QUALIFIER_GROUP_COUNT), 1);
        if (userGroupCount > accountSummary.groupsPerUserQuota) {
            // 超出限制，回退用户组的数量
            HBaseUtils.incrementColumnValue(user, Bytes.toBytes(User.QUALIFIER_GROUP_COUNT), -1);
            IAMErrorMessage errorMessage = new IAMErrorMessage("groupsPerUserQuota", 
                    "Cannot exceed quota for GroupsPerUser: %s.", accountSummary.groupsPerUserQuota);
            throw new IAMException(409, "LimitExceeded", errorMessage);
        }

        // 保存组下用户
        boolean groupUserCreated = HBaseUtils.checkAndCreate(param.getGroupUser());
        if (groupUserCreated) {
            // 组下用户数量加1
            HBaseUtils.incrementColumnValue(group, Bytes.toBytes(Group.QUALIFIER_USER_COUNT), 1);
        }
        
        // 保存用户的组
        boolean userGroupCreated = HBaseUtils.checkAndCreate(param.getUserGroup());
        if (!userGroupCreated) {
            // 保存失败，组数量减1
            HBaseUtils.incrementColumnValue(user, Bytes.toBytes(User.QUALIFIER_GROUP_COUNT), -1);
        }
        // 记录用户的修改事件，用于策略缓存的更新
        client.iamChangeEventInsert(new IamChangeEvent(ChangeType.USER, user.accountId, user.userName));
    }
    
    /**
     * 从指定的组中删除指定的用户
     * @param param
     * @throws BaseException 
     * @throws IOException 
     */
    public static void removeUserFromGroup(GroupUserParam param) throws BaseException, IOException {
        Group group = HBaseUtils.get(param.getGroup());
        // 没有找到组
        if (group == null) {
            throw ExceptionUtils.newNoSuchGroupException(param.groupName);
        }
        User user = HBaseUtils.get(param.getUser());
        // 没有找到用户
        if (user == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 删除组和用户关系
        boolean groupUserDeleted = HBaseUtils.checkAndDelete(param.getGroupUser());
        if (groupUserDeleted) {
            // 组下用户数量减1
            HBaseUtils.incrementColumnValue(group, Bytes.toBytes(Group.QUALIFIER_USER_COUNT), -1);
        }
        // 删除用户和组关系
        boolean userGroupDeleted = HBaseUtils.checkAndDelete(param.getUserGroup());
        if (userGroupDeleted) {
            // 用户加入组的数量减1
            HBaseUtils.incrementColumnValue(user, Bytes.toBytes(User.QUALIFIER_GROUP_COUNT), -1);
        }
        // 记录用户的修改事件，用于策略缓存的更新
        client.iamChangeEventInsert(new IamChangeEvent(ChangeType.USER, user.accountId, user.userName));
    }
    
    /**
     * 返回指定用户的组列表
     * @param param
     * @return
     * @throws Throwable 
     */
    public static ListGroupsForUserResult listGroupsForUser(ListGroupsForUserParam param) throws Throwable {
        // 获取用户信息
        User user = HBaseUtils.get(param.getUserParam());
        // 没有找到用户
        if (user == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 用户组查询条件
        UserGroup userGroupQuery = new UserGroup();
        userGroupQuery.accountId = user.accountId;
        userGroupQuery.userName = user.userName;
        Scan scan = HBaseUtils.buildScan(userGroupQuery.getUserPrefix(), param.marker);
        // 当marker为空，并且请求来自于proxy时获取数据总数
        boolean getTotal = param.marker == null && param.isFromConsole;
        // 获取用户组关系
        PageResult<UserGroup> userGroupPageResult = HBaseUtils.scan(scan, param.maxItems, UserGroup.class, getTotal);
        List<byte[]> groupRowKeys = new ArrayList<>();
        for (UserGroup userGroup : userGroupPageResult.list) {
            groupRowKeys.add(userGroup.getGroup().getRowKey());
        }
        // 批量获取组数据
        List<Group> groups = HBaseUtils.get(groupRowKeys, Group.class);
        PageResult<Group> pageResult = new PageResult<>();
        pageResult.list = groups;
        pageResult.isTruncated = userGroupPageResult.isTruncated;
        pageResult.marker = userGroupPageResult.marker;
        pageResult.total = userGroupPageResult.total;
        return new ListGroupsForUserResult(pageResult);
    }
}
