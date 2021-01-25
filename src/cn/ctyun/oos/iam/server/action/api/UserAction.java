package cn.ctyun.oos.iam.server.action.api;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.server.action.Action;
import cn.ctyun.oos.iam.server.entity.AccountPasswordPolicy;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.entity.Tag;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.entity.UserMFADevice;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.param.ChangePasswordParam;
import cn.ctyun.oos.iam.server.param.CreateLoginProfileParam;
import cn.ctyun.oos.iam.server.param.CreateUserParam;
import cn.ctyun.oos.iam.server.param.DeleteLoginProfileParam;
import cn.ctyun.oos.iam.server.param.DeleteUserParam;
import cn.ctyun.oos.iam.server.param.GetLoginProfileParam;
import cn.ctyun.oos.iam.server.param.GetUserParam;
import cn.ctyun.oos.iam.server.param.ListUserTagsParam;
import cn.ctyun.oos.iam.server.param.ListUsersParam;
import cn.ctyun.oos.iam.server.param.TagUserParam;
import cn.ctyun.oos.iam.server.param.UnTagUserParam;
import cn.ctyun.oos.iam.server.param.UpdateLoginProfileParam;
import cn.ctyun.oos.iam.server.param.UserType;
import cn.ctyun.oos.iam.server.result.CreateLoginProfileResult;
import cn.ctyun.oos.iam.server.result.CreateUserResult;
import cn.ctyun.oos.iam.server.result.GetLoginProfileResult;
import cn.ctyun.oos.iam.server.result.GetUserResult;
import cn.ctyun.oos.iam.server.result.ListUserTagsResult;
import cn.ctyun.oos.iam.server.result.ListUsersResult;
import cn.ctyun.oos.iam.server.result.PageResult;
import cn.ctyun.oos.iam.server.service.AccessKeyService;
import cn.ctyun.oos.iam.server.service.AccountPasswordPolicyService;
import cn.ctyun.oos.iam.server.service.AccountSummaryService;
import cn.ctyun.oos.iam.server.service.UserService;
import cn.ctyun.oos.iam.server.util.DateUtils;
import cn.ctyun.oos.iam.server.util.JSONUtils;
import cn.ctyun.oos.iam.server.util.Tags;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;

/**
 * IAM 用户接口
 * @author wangduo
 *
 */
@Action
public class UserAction {
    
    private static final Log log = LogFactory.getLog(UserAction.class);
    private static MetaClient client = MetaClient.getGlobalClient();
    
    /**
     * 创建子用户
     * @param param
     * @return
     * http://localhost:9097/?Action=CreateUser&UserName=testUser&Tags.member.1.Key=testkey&Tags.member.1.Value=testvalue
     * @throws Exception 
     */
    public static CreateUserResult createUser(CreateUserParam param) throws Exception  {
        User user = param.getUser();
        //判断标签的key是否重复
        if (user.tags != null && user.tags.size() != 0) {
        	Set<String> tagKeys = new HashSet<String>();
        	for (Tag tag : user.tags) {
        		tagKeys.add(tag.key.toLowerCase());
        	}
        	// 有重复的key报错
        	if (tagKeys.size() < user.tags.size()) {
        	    IAMErrorMessage errorMessage = new IAMErrorMessage("duplicateTagKey", 
        	            "Duplicate tag keys found. Please note that Tag keys are case insensitive.");
        		throw new IAMException(400, "InvalidInput", errorMessage);
        	}
        }        
        // 获取当前账户的使用及配额信息，对用户数和用户数配额进行判断
        AccountSummary accountSummary = AccountSummaryService.getAccountSummary(param.getAccountId());
        if (accountSummary.users >= accountSummary.usersQuota) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("usersQuota", 
                    "Cannot exceed quota for UsersPerAccount: %s.", accountSummary.usersQuota);
            throw new IAMException(409, "LimitExceeded", errorMessage);
        }
        // 判断是否存在 
        if (HBaseUtils.exist(user)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("userAlreadyExists", "User with name %s already exists.", user.userName);
            throw new IAMException(409, "EntityAlreadyExists", errorMessage);
        }
        
        // 创建一个proxy使用的AK
        AkSkMeta accessKey = new AkSkMeta(param.currentOwner.getId());
        accessKey.isRoot = 0;
        accessKey.userId = user.userId;
        accessKey.userName = user.userName;
        AkSkMeta accessKeyResult = AccessKeyService.create(accessKey);
        user.builtInAccessKey = accessKeyResult.accessKey;
        
        boolean created = HBaseUtils.checkAndCreate(user);
        if (created) {
            // 账户中的用户数量加1
            AccountSummaryService.increment(param.getAccountId(), AccountSummary.USERS, 1);
        } else {
            // 并发创建失败，删除之前常见的AK
            AccessKeyService.delete(accessKeyResult);
            IAMErrorMessage errorMessage = new IAMErrorMessage("userAlreadyExists", "User with name %s already exists.", user.userName);
            throw new IAMException(409, "EntityAlreadyExists", errorMessage);
        }
        return new CreateUserResult(user);
    }
    
    /**
     * 删除指定的IAM用户
     * @param param
     * @throws Throwable 
     */
    public static void deleteUser(DeleteUserParam param) throws Throwable {
        
        User user = param.getUser();
        user = HBaseUtils.get(user);
        if (user == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 如果请求来自于控制台
        if (param.isFromConsole) {
            // 删除用户关系数据
            UserService.deleteUserAttached(user, param);
        } else {
            // 删除冲突检查
            deleteConflictCheck(user, param);
        }
        // 先查询再删除
        boolean deleted = HBaseUtils.checkAndDelete(user);
        if (deleted) {
            // 账户中的用户数量减1
            AccountSummaryService.increment(param.getAccountId(), AccountSummary.USERS, -1);
            if (user.builtInAccessKey != null) {
                // 删除用户预置的accessKey
                AkSkMeta accessKey = new AkSkMeta(user.builtInAccessKey);
                client.akskDelete(accessKey);
            }
        }
    }
    
    /**
     * 用户删除冲突检查
     * 控制台访问时，将所有错误收集后进行返回
     * @param user
     * @param param
     * @return
     * @throws IOException
     * @throws BaseException
     */
    private static void deleteConflictCheck(User user, DeleteUserParam param) throws IOException, BaseException {
        IAMErrorMessage groupError = new IAMErrorMessage("userHasGroup", "Cannot delete entity, must remove users from group first.", param.userName);
        IAMErrorMessage passwordError = new IAMErrorMessage("userHasLoginProfile", "Cannot delete entity, must delete login profile first.", param.userName);
        IAMErrorMessage policyError = new IAMErrorMessage("userHasPolicy", "Cannot delete entity, must detach all policies first.", param.userName);
        IAMErrorMessage akError = new IAMErrorMessage("userHasAccessKey", "Cannot delete entity, must delete access keys first.", param.userName);
        IAMErrorMessage mfaError = new IAMErrorMessage("userHasMFA", "Cannot delete entity, must delete MFA device first.", param.userName);
        // 用户不得属于任何组，也不得拥有任何访问密钥，启用的MFA设备或附加策略
        if (user.groupCount != null && user.groupCount > 0) {
            throw new IAMException(409, "DeleteConflict", groupError);
        }
        if (!StringUtils.isEmpty(user.password)) {
            throw new IAMException(409, "DeleteConflict", passwordError);
        }
        if (user.policyCount != null && user.policyCount > 0) {
            throw new IAMException(409, "DeleteConflict", policyError);
        }
        if (user.accessKeys !=null && user.accessKeys.size() > 0) {
            throw new IAMException(409, "DeleteConflict", akError);
        }
        // 判断用户当前是否存在MFA
        UserMFADevice userMFADevice = new UserMFADevice();
        userMFADevice.userType = UserType.User.value;
        userMFADevice.accountId = user.accountId;
        userMFADevice.userName = user.userName;
        if (HBaseUtils.exist(userMFADevice)) {
            throw new IAMException(409, "DeleteConflict", mfaError);
        }
    }
    
    /**
     * 获取用户信息
     * @param param
     * @return
     * @throws IOException 
     * @throws BaseException 
     */
    public static GetUserResult getUser(GetUserParam param) throws IOException, BaseException {
        User user = null;
        if (param.isRoot() && param.userName == null) {
            // 获取根用户信息
            user = new User();
            // 根用户ID为账户ID
            user.userId = param.getAccountId();
            user.accountId = param.getAccountId();
            user.arn = user.getRootArn();
            OwnerMeta owner = param.currentOwner;
            user.userName = owner.name;
            try {
                // 根用户创建时间
                user.createDate = DateUtils.parseYYYYMMDD(owner.createDate).getTime();
            } catch (ParseException e) {
                log.error("parse owner " + owner.name + " createDate error.", e);
            }
            user.passwordLastUsed = owner.proxyLastLoginTime == -1 ? null : owner.proxyLastLoginTime;
            user.iPLastUsed = StringUtils.isEmpty(owner.proxyLastLoginIp) ? null : owner.proxyLastLoginIp;
        } else {
            // 获取子用户信息
            User userParam = param.getUserParam();
            user = HBaseUtils.get(userParam);
            // 没有找到用户
            if (user == null) {
                throw ExceptionUtils.newNoSuchUserException(param.userName);
            }
            user.arn = user.getArn();
        }
        return new GetUserResult(user);
    }
    
    /**
     * 列出具有指条件的IAM用户
     * @param param
     * @return
     * @throws Throwable 
     */
    public static ListUsersResult listUsers(ListUsersParam param) throws Throwable {
        Scan scan = HBaseUtils.buildScan(param.getAccountId(), param.marker);
        FilterList filterList = new FilterList();
        // 用户名模糊匹配
        if (param.userName != null) {
            SingleColumnValueFilter filter = new SingleColumnValueFilter(Bytes.toBytes(Qualifier.DEFAULT_FAMILY), Bytes.toBytes(User.QUALIFIER_USER_NAME), 
                    CompareOp.EQUAL, new SubstringComparator(param.userName));
            filterList.addFilter(filter);
        }
        if (param.accessKeyId != null) {
            SingleColumnValueFilter filter = new SingleColumnValueFilter(Bytes.toBytes(Qualifier.DEFAULT_FAMILY), Bytes.toBytes(User.QUALIFIER_ACCESSKEYS), 
                    CompareOp.EQUAL, new SubstringComparator(param.accessKeyId));
            filter.setFilterIfMissing(true);
            filterList.addFilter(filter);
        }
        if (filterList.getFilters().size() > 0) {
            scan.setFilter(filterList);
        }
        // 当marker为空，并且请求来自于proxy时获取数据总数
        boolean getTotal = param.marker == null && param.isFromConsole;
        PageResult<User> pageResult = HBaseUtils.scan(scan, param.maxItems, User.class, getTotal);
        return new ListUsersResult(pageResult);
    }
    
    /**
     * 向IAM用户添加一个或多个标签。如果Tag key已经存在，则会被新的value覆盖
     * @param param
     * @throws BaseException 
     * @throws IOException 
     */
    public static void tagUser(TagUserParam param) throws BaseException, IOException {
        User tagUser = param.getUserParam();
        //判断标签的key是否重复
        if (tagUser.tags != null && tagUser.tags.size() != 0) {
        	Set<String> tagKeys = new HashSet<String>();
        	for(Tag tag : tagUser.tags) {
        		tagKeys.add(tag.key.toLowerCase());
        	}
        	if(tagKeys.size() < tagUser.tags.size()) {
                IAMErrorMessage errorMessage = new IAMErrorMessage("duplicateTagKey", 
                        "Duplicate tag keys found. Please note that Tag keys are case insensitive.");
                throw new IAMException(400, "InvalidInput", errorMessage);
        	}
        }
        User existUser = HBaseUtils.get(tagUser);
        // 没有找到用户
        if (existUser == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        Map<String, Tag> tagMap = new LinkedHashMap<>();
        if (existUser.tags != null) {
            // 遍历用户原有标签放入map
            for (Tag tag : existUser.tags) {
                tagMap.put(tag.key.toLowerCase(), tag);
            }
        }
        // 遍历用户新标签放入map，key相同覆盖老标签
        for (Tag tag : tagUser.tags) {
            tagMap.put(tag.key.toLowerCase(), tag);
        }
        // 判断标签数量
        List<Tag> tags = new ArrayList<>(tagMap.values());
        if (tags.size() > Tags.TAGS_LIMIT_SIZE) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("userTagQuota", 
                    "The number of tags has reached the maximum limit.");
            throw new IAMException(409, "LimitExceeded", errorMessage);
        }
        tagUser.tags = tags;
        // 使用key排序，用于分页查询
        Collections.sort(tagUser.tags);
        // 保存标签,原子更新
        byte[] tagBytes = null;
        if (existUser.tags != null) {
            tagBytes = Bytes.toBytes(JSONUtils.toJSONArray(existUser.tags));
        }
        boolean success = HBaseUtils.checkAndPut(tagUser, Bytes.toBytes(Qualifier.DEFAULT_FAMILY), Bytes.toBytes(User.QUALIFIER_TAGS), tagBytes);
        if (!success) {
            throw new BaseException(409, "ConcurrentModification");
        }
    }
    
    /**
     * 从用户中删除指定的标记。删除的标签不存在时，也返回200成功。
     * @param param
     * @throws BaseException 
     * @throws IOException 
     */
    public static void untagUser(UnTagUserParam param) throws BaseException, IOException {
        //判断标签的key是否重复
        Set<String> tagKeys = new HashSet<String>();
        for(String tagKey : param.tagKeys) {
            tagKeys.add(tagKey.toLowerCase());
        }
        if(tagKeys.size() < param.tagKeys.size()) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("duplicateTagKey", 
                    "Duplicate tag keys found. Please note that Tag keys are case insensitive.");
            throw new IAMException(400, "InvalidInput", errorMessage);
        }
        
        User unTagUser = param.getUserParam();
        User existUser = HBaseUtils.get(unTagUser);
        // 没有找到用户
        if (existUser == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 用户没有标签不做处理
        if (existUser.tags == null) {
            return;
        }
        Map<String, Tag> tagMap = new LinkedHashMap<>();
        // 遍历用户原有标签放入map
        for (Tag tag : existUser.tags) {
            tagMap.put(tag.key.toLowerCase(), tag);
        }
        // 删除标签
        for (String tagKey : param.tagKeys) {
            tagMap.remove(tagKey.toLowerCase());
        }
        unTagUser.tags = new ArrayList<>(tagMap.values());
        // 使用key排序，用于分页查询
        Collections.sort(unTagUser.tags);
        // 保存标签,原子更新
        byte[] tagBytes = Bytes.toBytes(JSONUtils.toJSONArray(existUser.tags).toString());
        boolean success = HBaseUtils.checkAndPut(unTagUser, Bytes.toBytes(Qualifier.DEFAULT_FAMILY), 
                Bytes.toBytes(User.QUALIFIER_TAGS), tagBytes);
        if (!success) {
            throw new BaseException(409, "ConcurrentModification");
        }
    }
    
    /**
     * 列出附加到指定用户的标记。返回的标签列表按标签键排序。
     * @param param
     * @return
     * @throws BaseException
     * @throws IOException 
     */
    public static ListUserTagsResult listUserTags(ListUserTagsParam param) throws BaseException, IOException {
        User user = HBaseUtils.get(param.getUserParam());
        // 没有找到用户
        if (user == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        
        ListUserTagsResult result = new ListUserTagsResult();
        if (user.tags == null) {
            result.tags = Collections.emptyList();
            return result;
        }
        // 分页开始索引
        int fromIndex = 0;
        if (param.marker != null) {
            for (int i = 0; i < user.tags.size(); i++) {
                Tag tag = user.tags.get(i);
                if (param.marker.equals(tag.key)) {
                    fromIndex = i;
                }
            }
        }
        // 分页结束索引
        int toIndex = fromIndex + param.maxItems;
        if (toIndex >= user.tags.size()) {
            // 无后续分页
            result.tags = user.tags.subList(fromIndex, user.tags.size());
        } else {
            // 有后续分页
            result.tags = user.tags.subList(fromIndex, toIndex);
            result.isTruncated = true;
            result.marker = user.tags.get(toIndex).key;
        }
        // 当marker为空，并且请求来自于proxy时获取数据总数
        boolean getTotal = param.marker == null && param.isFromConsole;
        if (getTotal) {
            result.total = (long) result.tags.size();
        }
        
        return result;
    }
    
    /**
     * 更改当前用户的IAM用户的密码
     * root用户密码不受此操作的影响
     * @param param
     * @throws BaseException
     * @throws IOException
     */
    public static void changePassword(ChangePasswordParam param) throws BaseException, IOException {
        if (param.isRoot()) {
            throw new BaseException(403, "AccessDenied", "Only IAM Users can change their own password.");
        }
        // 获取用户数据
        User existUser = HBaseUtils.get(param.getCurrentUser());
        if (StringUtils.isEmpty(existUser.password)) {
            throw ExceptionUtils.newNoSuchLoginProfileException(existUser.userName);
        }
        
        // 新旧密码一样处理
        if (param.newPassword.equals(param.oldPassword)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("oldNewPasswordSame", 
                    "Policy constraint violation with password reuse prevention during password change.");
            throw new IAMException(400, "PasswordPolicyViolation", errorMessage);
        }
        // 验证旧密码是否匹配
        String oldPassword = IAMStringUtils.passwordEncode(param.oldPassword);
        if (!oldPassword.equals(existUser.password)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("oldPasswordIncorrect", "The old password was incorrect.");
            throw new IAMException(403, "AccessDenied", errorMessage);
        }
        
        // 验证新密码是否符合当前账户的密码策略
        validatePassword(existUser, param.newPassword, param.getAccountId());
        
        // 更新用户信息
        User newUser = param.getCurrentUser();
        // 密码加密存储
        newUser.password = IAMStringUtils.passwordEncode(param.newPassword);
        newUser.oldPasswords = existUser.oldPasswords;
        newUser.passwordCreateDate = System.currentTimeMillis();
        newUser.passwordResetRequired = false;
        HBaseUtils.put(newUser);
    }
    
    /**
     * 为指定用户创建密码，使用户能够通过OOS管理控制台访问
     * http://localhost:9097/?Action=CreateLoginProfile&Password=123456&UserName=testUser111
     * @param param
     * @return
     * @throws IOException 
     * @throws BaseException 
     */
    public static CreateLoginProfileResult createLoginProfile(CreateLoginProfileParam param) throws IOException, BaseException {
        User existedUser = HBaseUtils.get(param.getUser());
        // 没有找到用户
        if (existedUser == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 密码已存在
        if (StringUtils.isNotEmpty(existedUser.password)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("loginProfileAlreadyExists", "Login Profile for user %s already exists.", param.userName);
            throw new IAMException(409, "EntityAlreadyExists", errorMessage);
        }
        // 验证新密码是否符合当前账户的密码策略
        validatePassword(existedUser, param.password, param.getAccountId());
        // 更新用户
        User user = new User();
        user.accountId = existedUser.accountId;
        user.userName = existedUser.userName;
        // 保存用户密码数据
        user.password = IAMStringUtils.passwordEncode(param.password);
        user.oldPasswords = existedUser.oldPasswords;
        user.passwordCreateDate = System.currentTimeMillis();
        user.passwordResetRequired = param.passwordResetRequired;
        HBaseUtils.put(user);
        // 设置返回结果
        CreateLoginProfileResult result = new CreateLoginProfileResult();
        result.loginProfile.userName = param.userName;
        result.loginProfile.passwordResetRequired = param.passwordResetRequired;
        result.loginProfile.createDate = user.passwordCreateDate;
        return result;
    }

    /**
     * 更改指定IAM用户的密码
     * @param param
     * @throws IOException
     * @throws BaseException
     */
    public static void updateLoginProfile(UpdateLoginProfileParam param) throws IOException, BaseException {
        User existedUser = HBaseUtils.get(param.getUser());
        // 没有找到用户
        if (existedUser == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 密码不存在
        if (StringUtils.isEmpty(existedUser.password)) {
            throw ExceptionUtils.newNoSuchLoginProfileException(param.userName);
        }
        User user = new User();
        user.accountId = existedUser.accountId;
        user.userName = existedUser.userName;
        if (param.password != null) {
            // 验证新密码是否符合当前账户的密码策略
            validatePassword(existedUser, param.password, param.getAccountId());
            // 保存用户密码数据
            user.password = IAMStringUtils.passwordEncode(param.password);
            user.oldPasswords = existedUser.oldPasswords;
            user.passwordCreateDate = System.currentTimeMillis();
        }
        if (param.passwordResetRequired != null) {
            user.passwordResetRequired = param.passwordResetRequired;
        }
        if (param.password != null || param.passwordResetRequired != null) {
            HBaseUtils.put(user);
        }
    }

    /**
     * 删除指定IAM用户的密码
     * 这将终止用户通过OOS管理控制台访问OOS服务的能力
     * @param param
     * @throws BaseException 
     * @throws IOException 
     */
    public static void deleteLoginProfile(DeleteLoginProfileParam param) throws BaseException, IOException {
        User existedUser = HBaseUtils.get(param.getUser());
        // 没有找到用户
        if (existedUser == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 密码不存在
        if (StringUtils.isEmpty(existedUser.password)) {
            throw ExceptionUtils.newNoSuchLoginProfileException(param.userName);
        }
        User user = new User();
        user.accountId = existedUser.accountId;
        user.userName = existedUser.userName;
        user.password = "";
        HBaseUtils.put(user);
    }

    /**
     * 查询用户登录配置信息
     * @param param
     * @return
     * @throws IOException 
     * @throws BaseException 
     */
    public static GetLoginProfileResult getLoginProfile(GetLoginProfileParam param) throws IOException, BaseException {
        User existedUser = HBaseUtils.get(param.getUser());
        // 没有找到用户
        if (existedUser == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 密码不存在
        if (StringUtils.isEmpty(existedUser.password)) {
            throw ExceptionUtils.newNoSuchLoginProfileException(param.userName);
        }
        GetLoginProfileResult result = new GetLoginProfileResult();
        result.loginProfile.userName = existedUser.userName;
        result.loginProfile.passwordResetRequired = existedUser.passwordResetRequired;
        result.loginProfile.createDate = existedUser.passwordCreateDate;
        return result;
    }

    
    /**
     * 校验密码是够符合密码策略
     * @param user
     * @param password
     * @param accountId
     * @return
     * @throws BaseException
     * @throws IOException 
     */
    private static void validatePassword(User user, String password, String accountId) throws BaseException, IOException {
        
        // 获取账户密码策略
        AccountPasswordPolicy passwordPolicy = AccountPasswordPolicyService.getAccountPasswordPolicy(accountId);
        
        // 详细错误列表，供前端显示错误使用
        List<String> params = new ArrayList<>();
        
        // 是否验证通过
        boolean passed = true;
        // 小于最小长度要求
        if (password.length() < passwordPolicy.minimumPasswordLength) {
            passed = false;
            params.add("minLength" + passwordPolicy.minimumPasswordLength);
        }
        // 至少需要一个小写字母
        if(passwordPolicy.requireLowercaseCharacters) {
            if (!IAMStringUtils.containsLowercaseCharacter(password)) {
                passed = false;
                params.add("requireLowercase");
            }
        }
        // 至少需要一个数字
        if(passwordPolicy.requireNumbers) {
            if (!IAMStringUtils.containsNumber(password)) {
                passed = false;
                params.add("requireNumbers");
            }
        }
        // 至少需要一个非字母数字字符
        if(passwordPolicy.requireSymbols) {
            if (!StringUtils.containsAny(password, "!@#$%^&*()_+-=[]{}|'")) {
                passed = false;
                params.add("requireSymbols");
            }
        }
        // 至少需要一个大写字母
        if(passwordPolicy.requireUppercaseCharacters) {
            if (!IAMStringUtils.containsUppercaseCharacter(password)) {
                passed = false;
                params.add("requireUppercase");
            }
        }
        if (!passed) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("notConformPasswordPolicy", "Password does not conform to the account password policy.", params.toArray());
            throw new IAMException(400, "PasswordPolicyViolation", errorMessage);
        }
        // 历史密码处理
        oldPasswordsProcess(user, password, passwordPolicy);
    }
    
    /**
     * 历史密码处理
     * 判断新密码是否与记录的旧密码重复
     * 将新密码记录到历史密码中
     * @param user
     * @param newPassword
     * @param passwordPolicy
     * @throws BaseException
     */
    private static void oldPasswordsProcess(User user, String newPassword, AccountPasswordPolicy passwordPolicy) throws BaseException {
        if (passwordPolicy.passwordReusePrevention == 0) {
            return;
        }
        Queue<String> passwordQueue = new LinkedList<>();
        if (user.oldPasswords != null) {
            passwordQueue.addAll(user.oldPasswords);
        }
        // 超过历史数量，移除最前的密码
        while (passwordQueue.size() > passwordPolicy.passwordReusePrevention) {
            passwordQueue.poll();
        }
        String encodeNewPassword = IAMStringUtils.passwordEncode(newPassword);
        // 使用了记录的旧密码
        if (passwordQueue.contains(encodeNewPassword)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("useHistoryPassword", "Policy constraint violation with password reuse prevention during password change.");
            throw new IAMException(400, "PasswordPolicyViolation", errorMessage);
        }
        // 有老密码
        if (StringUtils.isNotEmpty(user.password)) {
            // 将老密码加入历史
            passwordQueue.offer(user.password);
        }
		if (passwordQueue.size() > passwordPolicy.passwordReusePrevention) {
			passwordQueue.poll();
		}
        // 将历史密码设置到当前用户中
        user.oldPasswords = new ArrayList<>(passwordQueue);
    }
    
}
