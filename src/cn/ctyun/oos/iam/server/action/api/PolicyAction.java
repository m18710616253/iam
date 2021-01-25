package cn.ctyun.oos.iam.server.action.api;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.filter.BinaryComparator;
import org.apache.hadoop.hbase.filter.CompareFilter.CompareOp;
import org.apache.hadoop.hbase.filter.Filter;
import org.apache.hadoop.hbase.filter.FilterList;
import org.apache.hadoop.hbase.filter.PrefixFilter;
import org.apache.hadoop.hbase.filter.SingleColumnValueFilter;
import org.apache.hadoop.hbase.filter.SubstringComparator;
import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;
import cn.ctyun.oos.iam.accesscontroller.policy.PolicyParseException;
import cn.ctyun.oos.iam.accesscontroller.util.ExceptionUtils;
import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;
import cn.ctyun.oos.iam.accesscontroller.util.IAMException;
import cn.ctyun.oos.iam.server.action.Action;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.entity.GroupPolicy;
import cn.ctyun.oos.iam.server.entity.ParseArnException;
import cn.ctyun.oos.iam.server.entity.Policy;
import cn.ctyun.oos.iam.server.entity.PolicyAttachmentCount;
import cn.ctyun.oos.iam.server.entity.PolicyEntity;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.entity.UserPolicy;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.param.CreatePolicyParam;
import cn.ctyun.oos.iam.server.param.DeletePolicyParam;
import cn.ctyun.oos.iam.server.param.GetPolicyParam;
import cn.ctyun.oos.iam.server.param.GroupPolicyParam;
import cn.ctyun.oos.iam.server.param.ListAttachedGroupPoliciesParam;
import cn.ctyun.oos.iam.server.param.ListAttachedUserPoliciesParam;
import cn.ctyun.oos.iam.server.param.ListEntitiesForPolicyParam;
import cn.ctyun.oos.iam.server.param.ListPoliciesParam;
import cn.ctyun.oos.iam.server.param.PolicyScopeType;
import cn.ctyun.oos.iam.server.param.UserPolicyParam;
import cn.ctyun.oos.iam.server.result.AttachedPolicy;
import cn.ctyun.oos.iam.server.result.CreatePolicyResult;
import cn.ctyun.oos.iam.server.result.GetPolicyResult;
import cn.ctyun.oos.iam.server.result.ListAttachedGroupPoliciesResult;
import cn.ctyun.oos.iam.server.result.ListAttachedUserPoliciesResult;
import cn.ctyun.oos.iam.server.result.ListEntitiesForPolicyResult;
import cn.ctyun.oos.iam.server.result.ListPoliciesResult;
import cn.ctyun.oos.iam.server.result.PageResult;
import cn.ctyun.oos.iam.server.service.AccountSummaryService;
import cn.ctyun.oos.iam.server.service.PolicyService;
import cn.ctyun.oos.metadata.IamChangeEvent;
import cn.ctyun.oos.metadata.IamChangeEvent.ChangeType;

/**
 * IAM 策略接口
 * @author wangduo
 *
 */
@Action
public class PolicyAction {
    
    private static final Log log = LogFactory.getLog(PolicyAction.class);
    
    private static MetaClient client = MetaClient.getGlobalClient();
    
    /**
     * 创建策略
     * http://localhost:9097/?Action=CreatePolicy&PolicyName=testPolicy&PolicyDocument={%22Version%22:%222012-10-17%22,%22Statement%22:{%22Effect%22:%22Allow%22,%22Action%22:%22*%22,%22Resource%22:%22*%22}}&Description=desc123
     * @param param
     * @return
     * @throws Exception 
     */
    public static CreatePolicyResult createPolicy(CreatePolicyParam param) throws Exception {
        
        Policy policy = param.getPolicy();
        
        // 获取当前账户的使用及配额信息，对策略数配额进行判断
        AccountSummary accountSummary = AccountSummaryService.getAccountSummary(param.getAccountId());
        if (accountSummary.policies >= accountSummary.policiesQuota) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("policiesPerAccountQuota", 
                    "Cannot exceed quota for PoliciesPerAccount: %s.", accountSummary.policiesQuota);
            throw new IAMException(409, "LimitExceeded", errorMessage);
        }
        
        // 解析policy，保证访问控制时可以正常解析
        try {
            AccessPolicy.fromJson(param.policyDocument);
        } catch (PolicyParseException e) {
            log.error("Parse policy json failed. policyDocument:" + param.policyDocument, e);
            
            throw new IAMException(400, "MalformedPolicyDocument", new IAMErrorMessage(e.messageCode, e.getMessage(), e.params));
        }
        
        boolean created = HBaseUtils.checkAndCreate(policy);
        if (created) {
            // 账户自定义策略加1
            AccountSummaryService.increment(param.getAccountId(), AccountSummary.POLICIES, 1);
        } else {
            // 策略已经存在则为更新
            policy.policyId = null;
            policy.createDate = null;
            policy.updateDate = System.currentTimeMillis();
            HBaseUtils.put(policy);
            // 获取最新内容
            policy = HBaseUtils.get(policy);
            // 获取attachmentCount
            PolicyAttachmentCount count = HBaseUtils.get(param.getPolicyAttachmentCount());
            if (count == null) {
                policy.attachmentCount = 0L;
            } else {
                policy.attachmentCount = count.count;
            }
            // 记录策略的修改事件，用于策略缓存的更新
            client.iamChangeEventInsert(new IamChangeEvent(ChangeType.POLICY, policy.accountId, policy.policyName));
        }
        
        return new CreatePolicyResult(policy);
    }
    
    /**
     * 删除指定的IAM策略
     * 在删除托管策略之前，必须先将策略与其附加到的所有用户，组分离
     * http://localhost:9097/?Action=DeletePolicy&PolicyArn=arn:ctyun:iam::0000000kf12oi:policy/testPolicy
     * @param param
     * @throws Throwable 
     */
    public static void deletePolicy(DeletePolicyParam param) throws Throwable {
        Policy policy = getPolicyFromArn(param.policyArn, param.getAccountId());
        // 不允许删除系统策略
        if (PolicyScopeType.OOS.value.equalsIgnoreCase(policy.accountId)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("policyOutsideAccount", "Policy is outside your own account.", param.policyArn);
            throw new IAMException(403, "AccessDenied", errorMessage);
        }
        // 获取策略的附加计数
        PolicyAttachmentCount policyAttachmentCount = new PolicyAttachmentCount(policy, param.getAccountId());
        policyAttachmentCount = HBaseUtils.get(policyAttachmentCount);
        
        // 如果请求来自于控制台
        if (param.isFromConsole) {
            // 删除策略关系数据
            PolicyService.deletePolicyAttached(policy, param);
        } else {
            // 如果策略还有被附加，不允许删除
            if (policyAttachmentCount != null && policyAttachmentCount.count != null && policyAttachmentCount.count != 0L) {
                IAMErrorMessage errorMessage = new IAMErrorMessage("deletePolicyAttachedEntity", "Cannot delete a policy attached to entities.", param.policyArn);
                throw new IAMException(409, "DeleteConflict", errorMessage);
            }
        }
        // 删除策略
        boolean deleted = HBaseUtils.checkAndDelete(policy);
        if (deleted) {
            // 账户自定义策略减1
            AccountSummaryService.increment(param.getAccountId(), AccountSummary.POLICIES, -1);
        } else {
            throw ExceptionUtils.newNoSuchPolicyException(param.policyArn);
        }
        if (policyAttachmentCount != null) {
            // 删除策略附加计数
            HBaseUtils.delete(policyAttachmentCount);
        }
    }

    /**
     * 获取指定的IAM策略
     * http://localhost:9097/?Action=GetPolicy&PolicyArn=arn:ctyun:iam::0000000kf12oi:policy/testPolicy
     * @param param
     * @throws BaseException 
     * @throws IOException 
     */
    public static GetPolicyResult getPolicy(GetPolicyParam param) throws BaseException, IOException {
        Policy policy = getPolicyFromArn(param.policyArn, param.getAccountId());

        // 获取策略的附加计数
        PolicyAttachmentCount policyAttachmentCount = new PolicyAttachmentCount(policy, param.getAccountId());
        policyAttachmentCount = HBaseUtils.get(policyAttachmentCount);
        if (policyAttachmentCount == null) {
            policy.attachmentCount = 0L;
        } else {
            policy.attachmentCount = policyAttachmentCount.count;
        }
        return new GetPolicyResult(policy);
    }
    

    /**
     * 将指定的托管策略附加到指定的用户
     * http://localhost:9097/?Action=AttachUserPolicy&PolicyArn=arn:ctyun:iam::0000000kf12oi:policy/testPolicy&UserName=testUser
     * @param param
     * @throws Exception 
     */
    public static void attachUserPolicy(UserPolicyParam param) throws Exception {
        
        Policy policy = getPolicyFromArn(param.policyArn, param.getAccountId());
        User user = HBaseUtils.get(param.getUser());
        // 没有找到用户
        if (user == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 获取当前账户的使用及配额信息
        AccountSummary accountSummary = AccountSummaryService.getAccountSummary(param.getAccountId());
        // 先增加用户策略计数，防止并发附加
        long userPolicyCount = HBaseUtils.incrementColumnValue(user, Bytes.toBytes(User.QUALIFIER_POLICY_COUNT), 1);
        // 判断用户策略数限制
        if (userPolicyCount > accountSummary.attachedPoliciesPerUserQuota) {
            // 超过数量，回退计数
            HBaseUtils.incrementColumnValue(user, Bytes.toBytes(User.QUALIFIER_POLICY_COUNT), -1);
            IAMErrorMessage errorMessage = new IAMErrorMessage("attachedPoliciesPerUserQuota", 
                    "Cannot exceed quota for PoliciesPerUser: %s.", accountSummary.attachedPoliciesPerUserQuota);
            throw new IAMException(409, "LimitExceeded", errorMessage);
        }
        // 保存策略附加的用户
        PolicyEntity policyUser = param.getPolicyUser(policy, user);
        boolean policyUserCreated = HBaseUtils.checkAndCreate(policyUser);
        if (policyUserCreated) {
            // 增加策略附加计数
            incrementAttachmentCount(policy, param.getAccountId(), 1);
        }
        // 保存用户被附加的策略
        boolean userPolicyCreated = HBaseUtils.checkAndCreate(param.getUserPolicy(policy));
        if (!userPolicyCreated) {
            // 附加失败，回退计数
            HBaseUtils.incrementColumnValue(user, Bytes.toBytes(User.QUALIFIER_POLICY_COUNT), -1);
        }
        // 记录用户的修改事件，用于策略缓存的更新
        client.iamChangeEventInsert(new IamChangeEvent(ChangeType.USER, user.accountId, user.userName));
    }
    
    /**
     * 从指定的用户中删除指定的托管策略
     * http://localhost:9097/?Action=DetachUserPolicy&PolicyArn=arn:ctyun:iam::0000000kf12oi:policy/testPolicy&UserName=testUser
     * @param param
     * @throws BaseException 
     * @throws IOException 
     */
    public static void detachUserPolicy(UserPolicyParam param) throws BaseException, IOException {
        Policy policy = getPolicyFromArn(param.policyArn, param.getAccountId());
        User user = HBaseUtils.get(param.getUser());
        // 没有找到用户
        if (user == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 移除策略附加的用户
        PolicyEntity policyUser = param.getPolicyUser(policy, user);
        boolean policyUserDeleted = HBaseUtils.checkAndDelete(policyUser);
        if (policyUserDeleted) {
            // 减少策略附加计数
            incrementAttachmentCount(policy, param.getAccountId(), -1);
        }
        // 移除用户被附加的策略
        boolean userPolicyDeleted = HBaseUtils.checkAndDelete(param.getUserPolicy(policy));
        if (userPolicyDeleted) {
            // 减少用户策略计数
            HBaseUtils.incrementColumnValue(user, Bytes.toBytes(User.QUALIFIER_POLICY_COUNT), -1);
        }
        // 记录用户的修改事件，用于策略缓存的更新
        client.iamChangeEventInsert(new IamChangeEvent(ChangeType.USER, user.accountId, user.userName));
    }
    
    /**
     * 将指定的托管策略附加到指定的组
     * http://localhost:9097/?Action=AttachGroupPolicy&PolicyArn=arn:ctyun:iam::0000000kf12oi:policy/testPolicy&GroupName=testGroup
     * @param param
     * @throws Exception 
     */
    public static void attachGroupPolicy(GroupPolicyParam param) throws Exception {
        Policy policy = getPolicyFromArn(param.policyArn, param.getAccountId());
        Group group = HBaseUtils.get(param.getGroup());
        // 没有找到组
        if (group == null) {
            throw ExceptionUtils.newNoSuchGroupException(param.groupName);
        }
        // 获取当前账户的使用及配额信息，对用户策略数和配额进行判断
        AccountSummary accountSummary = AccountSummaryService.getAccountSummary(param.getAccountId());
        // 先增加组策略计数，防止并发附加
        long groupPolicyCount = HBaseUtils.incrementColumnValue(group, Bytes.toBytes(Group.QUALIFIER_POLICY_COUNT), 1);
        // 判断组策略数限制
        if (groupPolicyCount > accountSummary.attachedPoliciesPerGroupQuota) {
            // 超过数量，回退计数
            HBaseUtils.incrementColumnValue(group, Bytes.toBytes(Group.QUALIFIER_POLICY_COUNT), -1);
            IAMErrorMessage errorMessage = new IAMErrorMessage("attachedPoliciesPerGroupQuota", 
                    "Cannot exceed quota for PoliciesPerGroup: %s.", accountSummary.attachedPoliciesPerGroupQuota);
            throw new IAMException(409, "LimitExceeded", errorMessage);
        }
        
        // 保存策略附加的组
        PolicyEntity policyEntity = param.getPolicyEntity(policy, group);
        boolean policyEntityCreated = HBaseUtils.checkAndCreate(policyEntity);
        if (policyEntityCreated) {
            // 增加策略附加计数
            incrementAttachmentCount(policy, param.getAccountId(), 1);
        }
        // 保存组被附加的策略
        boolean groupPolicyCreated = HBaseUtils.checkAndCreate(param.getGroupPolicy(policy));
        if (!groupPolicyCreated) {
            // 附加失败，减少组用户策略计数
            HBaseUtils.incrementColumnValue(group, Bytes.toBytes(Group.QUALIFIER_POLICY_COUNT), -1);
        }
        // 记录组的修改事件，用于策略缓存的更新
        client.iamChangeEventInsert(new IamChangeEvent(ChangeType.GROUP, group.accountId, group.groupName));
    }
    
    /**
     * 从指定的组中删除指定的托管策略
     * http://localhost:9097/?Action=DetachGroupPolicy&PolicyArn=arn:ctyun:iam::0000000kf12oi:policy/testPolicy&GroupName=testGroup
     * @param param
     * @throws BaseException 
     * @throws IOException 
     */
    public static void detachGroupPolicy(GroupPolicyParam param) throws BaseException, IOException {
        Policy policy = getPolicyFromArn(param.policyArn, param.getAccountId());
        Group group = HBaseUtils.get(param.getGroup());
        // 没有找到组
        if (group == null) {
            throw ExceptionUtils.newNoSuchGroupException(param.groupName);
        }
        // 移除策略附加的组
        PolicyEntity policyEntity = param.getPolicyEntity(policy, group);
        boolean policyEntityDeleted = HBaseUtils.checkAndDelete(policyEntity);
        if (policyEntityDeleted) {
            // 减少策略附加计数
            incrementAttachmentCount(policy, param.getAccountId(), -1);
        }
        // 移除组被附加的策略
        boolean groupPolicyDeleted = HBaseUtils.checkAndDelete(param.getGroupPolicy(policy));
        if (groupPolicyDeleted) {
            // 减少组策略计数
            HBaseUtils.incrementColumnValue(group, Bytes.toBytes(Group.QUALIFIER_POLICY_COUNT), -1);
        }
        // 记录组的修改事件，用于策略缓存的更新
        client.iamChangeEventInsert(new IamChangeEvent(ChangeType.GROUP, group.accountId, group.groupName));
    }
    
    /**
     * 列出附加到指定IAM用户的所有托管策略
     * http://localhost:9097/?Action=ListAttachedUserPolicies&UserName=testUser
     * @param param
     * @return
     * @throws Throwable 
     */
    public static ListAttachedUserPoliciesResult listAttachedUserPolicies(ListAttachedUserPoliciesParam param) throws Throwable {
        
        // 没有找到用户
        if (!HBaseUtils.exist(param.getUserParam())) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 查询用户策略
        Scan scan = HBaseUtils.buildScan(param.getUserPolicy().getUserPolicyPrefix(), param.marker);
        // 当marker为空，并且请求来自于proxy时获取数据总数
        boolean getTotal = param.marker == null && param.isFromConsole;
        // 获取用户策略关系
        PageResult<UserPolicy> userPolicyPageResult = HBaseUtils.scan(scan, param.maxItems, UserPolicy.class, getTotal);
        // 设置策略rowKey列表
        List<byte[]> policyRowKeys = new ArrayList<>();
        for (UserPolicy userPolicy : userPolicyPageResult.list) {
            policyRowKeys.add(userPolicy.getPolicy().getRowKey());
        }
        // 批量获取策略
        List<Policy> policies = HBaseUtils.get(policyRowKeys, Policy.class);
        // 设置返回结果
        List<AttachedPolicy> resultPolicies = new ArrayList<>();
        for (Policy policy : policies) {
            AttachedPolicy resultPolicy = new AttachedPolicy();
            resultPolicy.policyArn = policy.getArn();
            resultPolicy.policyName = policy.policyName;
            resultPolicy.scope = policy.scope;
            resultPolicy.description = policy.description;
            resultPolicies.add(resultPolicy);
        }
        ListAttachedUserPoliciesResult result = new ListAttachedUserPoliciesResult();
        result.attachedPolicies = resultPolicies;
        result.isTruncated = userPolicyPageResult.isTruncated;
        result.marker = userPolicyPageResult.marker;
        result.total = userPolicyPageResult.total;
        return result;
    }
    
    /**
     * 列出附加到指定IAM组的所有托管策略
     * http://localhost:9097/?Action=ListAttachedGroupPolicies&GroupName=testGroup
     * @param param
     * @return
     * @throws Throwable 
     */
    public static ListAttachedGroupPoliciesResult listAttachedGroupPolicies(ListAttachedGroupPoliciesParam param) throws Throwable {
        
        // 没有找到组
        if (!HBaseUtils.exist(param.getGroupParam())) {
            throw ExceptionUtils.newNoSuchGroupException(param.groupName);
        }
        // 查询组下策略
        Scan scan = HBaseUtils.buildScan(param.getGroupPolicy().getGroupPolicyPrefix(), param.marker);
        // 当marker为空，并且请求来自于proxy时获取数据总数
        boolean getTotal = param.marker == null && param.isFromConsole;
        PageResult<GroupPolicy> groupPolicyPageResult = HBaseUtils.scan(scan, param.maxItems, GroupPolicy.class, getTotal);
        // 设置策略rowKey列表
        List<byte[]> policyRowKeys = new ArrayList<>();
        for (GroupPolicy groupPolicy : groupPolicyPageResult.list) {
            policyRowKeys.add(groupPolicy.getPolicy().getRowKey());
        }
        // 批量获取策略
        List<Policy> policies = HBaseUtils.get(policyRowKeys, Policy.class);
        // 设置返回结果
        List<AttachedPolicy> resultPolicies = new ArrayList<>();
        for (Policy policy : policies) {
            AttachedPolicy resultPolicy = new AttachedPolicy();
            resultPolicy.policyArn = policy.getArn();
            resultPolicy.policyName = policy.policyName;
            resultPolicy.scope = policy.scope;
            resultPolicy.description = policy.description;
            resultPolicies.add(resultPolicy);
        }
        ListAttachedGroupPoliciesResult result = new ListAttachedGroupPoliciesResult();
        result.attachedPolicies = resultPolicies;
        result.isTruncated = groupPolicyPageResult.isTruncated;
        result.marker = groupPolicyPageResult.marker;
        result.total = groupPolicyPageResult.total;
        
        return result;
    }
    
    /**
     * 列出指定托管策略所附加的所有IAM用户和组
     * http://localhost:9097/?Action=ListEntitiesForPolicy&PolicyArn=arn:ctyun:iam::0000000kf12oi:policy/testPolicy
     * @param param
     * @return
     * @throws Throwable 
     */
    public static ListEntitiesForPolicyResult listEntitiesForPolicy(ListEntitiesForPolicyParam param) throws Throwable {
        Policy policy = getPolicyFromArn(param.policyArn, param.getAccountId());
        Scan scan = HBaseUtils.buildScan(param.getRowPrefix(policy), param.marker);
        // 当marker为空，并且请求来自于proxy时获取数据总数
        boolean getTotal = param.marker == null && param.isFromConsole;
        PageResult<PolicyEntity> pageResult = HBaseUtils.scan(scan, param.maxItems, PolicyEntity.class, getTotal);
        ListEntitiesForPolicyResult result = new ListEntitiesForPolicyResult(pageResult);
        return result;
    }
    
    /**
     * 列出账户中可用的所有策略,包括系统策略和自定义策略
     * http://localhost:9097/?Action=ListPolicies
     * @param param
     * @return
     * @throws Throwable 
     */
    public static ListPoliciesResult listPolicies(ListPoliciesParam param) throws Throwable {
        
        Scan scan = new Scan();

        FilterList filterList = new FilterList();
        // 策略名称模糊匹配
        if (param.policyName != null) {
            Filter filter = new SingleColumnValueFilter(Bytes.toBytes(Qualifier.DEFAULT_FAMILY), Bytes.toBytes(Policy.QUALIFIER_POLICY_NAME), 
                    CompareOp.EQUAL, new SubstringComparator(param.policyName));
            filterList.addFilter(filter);
        }
        
        String oosPrefix; 
        String localPrefix;
        // 如果需要查询仅被附加过的策略
        if (param.isOnlyAttached()) {
            // 查询附加计数中count大于0的数据
            SingleColumnValueFilter attachedFilter = new SingleColumnValueFilter(Bytes.toBytes(Qualifier.DEFAULT_FAMILY), 
                    Bytes.toBytes(PolicyAttachmentCount.QUALIFIER_COUNT), CompareOp.GREATER, new BinaryComparator(Bytes.toBytes(0L)));
            attachedFilter.setFilterIfMissing(true);
            filterList.addFilter(attachedFilter);
            // 使用计数数据进行查询
            oosPrefix = "count|" + param.getAccountId() + "|" + PolicyScopeType.OOS.name() + "|";
            localPrefix = "count|" + param.getAccountId() + "|" + PolicyScopeType.Local.name() + "|";
        } else {
            oosPrefix = PolicyScopeType.OOS.name() + "|";
            localPrefix = param.getAccountId() + "|";
        }
        PrefixFilter oosFIilter = new PrefixFilter(Bytes.toBytes(oosPrefix));
        PrefixFilter localFIilter = new PrefixFilter(Bytes.toBytes(localPrefix));
        
        // 获取查询的作用域范围 
        PolicyScopeType policyScopeType = PolicyScopeType.fromValue(param.scope);
        // 对作用域进行查询
        FilterList rowkeyFilter = new FilterList(FilterList.Operator.MUST_PASS_ONE);
        if (policyScopeType == null || policyScopeType == PolicyScopeType.All) {
            rowkeyFilter.addFilter(oosFIilter);
            rowkeyFilter.addFilter(localFIilter);
            // 设置startRow
            String startPrefix = oosPrefix.compareTo(localPrefix) < 0 ? oosPrefix : localPrefix;
            scan.setStartRow(Bytes.toBytes(startPrefix));
            // 设置stopRow
            String stopPrefix = oosPrefix.compareTo(localPrefix) > 0 ? oosPrefix : localPrefix;
            scan.setStopRow(Bytes.toBytes(stopPrefix + Character.MAX_VALUE));
        } else if (policyScopeType == PolicyScopeType.OOS) {
            rowkeyFilter.addFilter(oosFIilter);
            // 设置startRow
            scan.setStartRow(Bytes.toBytes(oosPrefix));
            // 设置stopRow
            scan.setStopRow(Bytes.toBytes(oosPrefix + Character.MAX_VALUE));
        } else if (policyScopeType == PolicyScopeType.Local) {
            rowkeyFilter.addFilter(localFIilter);
            // 设置startRow
            scan.setStartRow(Bytes.toBytes(localPrefix));
            // 设置stopRow
            scan.setStopRow(Bytes.toBytes(localPrefix + Character.MAX_VALUE));

        } 
        filterList.addFilter(rowkeyFilter);
        if (filterList.getFilters().size() > 0) {
            scan.setFilter(filterList);
        }
        
        // marker设置
        if (param.marker != null) {
            scan.setStartRow(Bytes.toBytes(param.marker + Character.MIN_VALUE));
        }
        // 当marker为空，并且请求来自于proxy时获取数据总数
        boolean getTotal = param.marker == null && param.isFromConsole;
        PageResult<Policy> pageResult;
        // 查询计数数据
        if (param.isOnlyAttached()) {
            PageResult<PolicyAttachmentCount> countPageResult = HBaseUtils.scan(scan, param.maxItems, PolicyAttachmentCount.class, getTotal);
            //批量获取策略
            List<byte[]> rowKeys = new ArrayList<byte[]>();
            for (PolicyAttachmentCount count : countPageResult.list) {
                rowKeys.add(count.getPolicy().getRowKey());
            }
            List<Policy> policies = HBaseUtils.get(rowKeys, Policy.class);
            //  设置attachmentCount
            setAttachmentCountToPolicy(countPageResult.list, policies);
            // 设置返回结果
            pageResult = new PageResult<Policy>();
            pageResult.list = policies;
            pageResult.isTruncated = countPageResult.isTruncated;
            pageResult.marker = countPageResult.marker;
            pageResult.total = countPageResult.total;
        } else {
            pageResult = HBaseUtils.scan(scan, param.maxItems, Policy.class, getTotal);
            // 获取attachmentCount
            List<byte[]> rowKeys = new ArrayList<byte[]>();
            for (Policy policy : pageResult.list) {
                rowKeys.add(policy.getAttachmentCountRowKey(param.getAccountId()));
            }
            List<PolicyAttachmentCount> policyAttachmentCounts = HBaseUtils.get(rowKeys, PolicyAttachmentCount.class);
            // 设置attachmentCount
            setAttachmentCountToPolicy(policyAttachmentCounts, pageResult.list);
        }
        
        ListPoliciesResult result = new ListPoliciesResult(pageResult);
        return result;
    }
    
    /**
     * 将附加计数设置到策略中
     * @param counts
     * @param policies
     */
    private static void setAttachmentCountToPolicy(List<PolicyAttachmentCount> counts, List<Policy> policies) {
        Map<String, Long> countMap = new HashMap<>();
        for (PolicyAttachmentCount count : counts) {
            countMap.put(Bytes.toString(count.getPolicy().getRowKey()), count.count);
        }
        for (Policy policy : policies) {
            Long count = countMap.get(Bytes.toString(policy.getRowKey()));
            policy.attachmentCount = count == null ? 0L : count;
        }
    }
    
    /**
     * 通过policyArn获取policy
     * @param policyArn
     * @return
     * @throws BaseException
     * @throws IOException
     */
    private static Policy getPolicyFromArn(String policyArn, String accountId) throws BaseException, IOException {
        Policy policy = new Policy();
        try {
            policy.parseArn(policyArn);
        } catch (ParseArnException e) {
            log.error("ARN " + policyArn + " is not valid.", e);
            IAMErrorMessage errorMessage = new IAMErrorMessage("arnInvalid", "ARN %s is not valid.", policyArn);
            throw new IAMException(400, "InvalidInput", errorMessage);
        }
        Policy existPolicy = HBaseUtils.get(policy);
        if (existPolicy == null) {
            throw ExceptionUtils.newNoSuchPolicyException(policyArn);
        }
        // 不是系统策略且账户对不上
        if (!policy.accountId.equalsIgnoreCase(PolicyScopeType.OOS.value) && !policy.accountId.equals(accountId)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("policyOutsideAccount", "Policy is outside your own account.", policyArn);
            throw new IAMException(403, "AccessDenied", errorMessage);
        }
        return existPolicy;
    }
    
    /**
     * 增加策略的附加计数
     * @param policy
     * @param attachedAccountId 被附加的账户ID，系统策略时policy的accountId不能直接使用
     * @param count
     * @throws IOException
     */
    private static void incrementAttachmentCount(Policy policy, String attachedAccountId, long count) throws IOException {
        
        PolicyAttachmentCount policyAttachmentCount = new PolicyAttachmentCount();
        policyAttachmentCount.accountId = attachedAccountId;
        policyAttachmentCount.policyName = policy.policyName;
        policyAttachmentCount.scope = policy.scope;
        policyAttachmentCount.count = count;
        
        // 不存在则创建一条新数据
        boolean created = HBaseUtils.checkAndCreate(policyAttachmentCount);
        if (!created) {
            // 存在则增加count
            HBaseUtils.incrementColumnValue(policyAttachmentCount, Bytes.toBytes(PolicyAttachmentCount.QUALIFIER_COUNT), count);
        }
        // 如果是系统策略，记录被附加数量
        HBaseUtils.incrementColumnValue(policy, Bytes.toBytes(Policy.QUALIFIER_ATTACHED_TOTAL), count);
    }
    
}
