package cn.ctyun.oos.iam.server.action.api;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.util.ExceptionUtils;
import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;
import cn.ctyun.oos.iam.accesscontroller.util.IAMException;
import cn.ctyun.oos.iam.server.action.Action;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.param.CreateAccessKeyParam;
import cn.ctyun.oos.iam.server.param.DeleteAccessKeyParam;
import cn.ctyun.oos.iam.server.param.ListAccessKeysParam;
import cn.ctyun.oos.iam.server.param.UpdateAccessKeyParam;
import cn.ctyun.oos.iam.server.result.CreateAccessKeyResult;
import cn.ctyun.oos.iam.server.result.ListAccessKeysResult;
import cn.ctyun.oos.iam.server.service.AccessKeyService;
import cn.ctyun.oos.iam.server.service.AccountSummaryService;
import cn.ctyun.oos.iam.server.util.JSONUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.IamChangeEvent;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.IamChangeEvent.ChangeType;

/**
 * Access Key 相关请求处理
 * @author wangduo
 *
 */
@Action
public class AccessKeyAction {
    
    private static final Log log = LogFactory.getLog(AccessKeyAction.class);
    private static MetaClient client = MetaClient.getGlobalClient();
    
    /**
     * createAccessKey接口，创建AccessKey
     * @param baseParameter
     * @return
     * @throws Exception
     */
    public static CreateAccessKeyResult createAccessKey(CreateAccessKeyParam param) throws Exception {
        
        AkSkMeta accessKey = null;
        if (param.isRoot() && param.userName == null) {
            // 创建根用户AK
            accessKey = createRootAccessKey(param);
        } else {
            // 创建子用户AK
            accessKey = createUserAccessKey(param);
        }
        // 返回结果
        CreateAccessKeyResult result = new CreateAccessKeyResult();
        if (accessKey.isRoot == 1) {
            result.accessKey.userName = param.currentOwner.getName();
        } else {
            result.accessKey.userName = accessKey.userName;
        }
        result.accessKey.status = "Active";
        result.accessKey.accessKeyId = accessKey.accessKey;
        result.accessKey.secretAccessKey = accessKey.getSecretKey();
        result.accessKey.createDate = accessKey.createDate;
        return result;
    }
    
    /**
     * 创建根用户AK
     * @param param
     * @return
     * @throws Exception
     */
    private static AkSkMeta createRootAccessKey(CreateAccessKeyParam param) throws Exception {
        // 获取当前账户的使用及配额信息
        AccountSummary accountSummary = AccountSummaryService.getAccountSummary(param.getAccountId());
        // 从数据库中获取最新数据
        OwnerMeta owner = new OwnerMeta(param.currentOwner.name);
        client.ownerSelect(owner);
        if (owner.currentAKNum + 1 > accountSummary.accessKeysPerAccountQuota) {
            // 根用户AK数量超过限制
            IAMErrorMessage errorMessage = new IAMErrorMessage("accessKeysPerAccountQuota", 
                    "Cannot exceed quota for AccessKeysPerAccount: %s.", accountSummary.accessKeysPerAccountQuota);
            throw new IAMException(409, "LimitExceeded", errorMessage);
        }
        // AK数量加1
        client.ownerUpdateCurrentAKNum(param.currentOwner, true);
        // 创建AK
        AkSkMeta accessKey = new AkSkMeta(param.currentOwner.getId());
        AkSkMeta accessKeyResult = AccessKeyService.create(accessKey);
        log.info(param.currentOwner.getName() + " generate root access secret key success: " + accessKey.accessKey);
        return accessKeyResult;
    }
    
    /**
     * 创建子用户AK
     * @param parameter
     * @return
     * @throws Exception
     */
    private static AkSkMeta createUserAccessKey(CreateAccessKeyParam param) throws Exception {

        // 原用户信息
        User existUser = HBaseUtils.get(param.getUserParam());
        // 没有找到用户
        if (existUser == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 获取当前账户的使用及配额信息
        AccountSummary accountSummary = AccountSummaryService.getAccountSummary(param.getAccountId());
        // user AK数量验证
        if (existUser.accessKeys != null && existUser.accessKeys.size() >= accountSummary.accessKeysPerUserQuota) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("accessKeysPerUserQuota", 
                    "Cannot exceed quota for AccessKeysPerUser: %s.", accountSummary.accessKeysPerUserQuota);
            throw new IAMException(409, "LimitExceeded", errorMessage);
        }
        AkSkMeta accessKey = new AkSkMeta(param.currentOwner.getId());
        accessKey.isRoot = 0;
        accessKey.userId = existUser.userId;
        accessKey.userName = existUser.userName;
        AkSkMeta accessKeyResult = AccessKeyService.create(accessKey);
        // 维护子用户的AK
        User newUser = new User();
        newUser.accountId = existUser.accountId;
        newUser.userName = existUser.userName;
        newUser.accessKeys = existUser.accessKeys;
        if (newUser.accessKeys == null) {
            newUser.accessKeys = new ArrayList<>();
        }
        
        String oldAccessKeyIds = JSONUtils.toJSONArray(existUser.accessKeys);
        newUser.accessKeys.add(accessKey.accessKey);
        // 升序排序
        Collections.sort(newUser.accessKeys);
        // 更新用户AK ID列表
        updateUserAccessKeyIds(newUser, oldAccessKeyIds);
        log.info("accountId[" + param.getAccountId() + "] generate user[" + param.getUserParam().userName + "] access secret key success:" + accessKey.accessKey);
        return accessKeyResult;
    }
    
    /**
     * 更新用户AK ID列表
     * @param akUser
     * @param oldAccessKeyIds
     * @throws BaseException
     * @throws IOException 
     */
    private static void updateUserAccessKeyIds(User akUser, String oldAccessKeyIds) throws BaseException, IOException {
        // 原AK信息
        byte[] accessKeysBytes = null;
        if (oldAccessKeyIds != null) {
            accessKeysBytes = Bytes.toBytes(oldAccessKeyIds);
        }
        // 将accessKeyId维护到子用户信息中，原子更新
        boolean success = HBaseUtils.checkAndPut(akUser, Bytes.toBytes(Qualifier.DEFAULT_FAMILY), Bytes.toBytes(User.QUALIFIER_ACCESSKEYS), accessKeysBytes);
        if (!success) {
            throw new BaseException(409, "ConcurrentModification");
        }
    }
    
    /**
     * updateAccessKey接口，更新AccessKey状态
     * @throws IOException 
     */
    public static void updateAccessKey(UpdateAccessKeyParam param) throws BaseException, IOException {
        
        // 指定用户不存在
        if (param.userName != null && !HBaseUtils.exist(param.getUserParam())) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 获取AK
        AkSkMeta accessKey = new AkSkMeta(param.accessKeyId);
        boolean exist = client.akskSelect(accessKey);
        // 如果修改的AK不属于指定的用户
        if (!exist || !userHasTheAccessKey(param.userName, param, accessKey)) {
            throw ExceptionUtils.newNoSuchAccessKeyException(param.accessKeyId);
        }
        
        // 设置状态
        accessKey.status = param.getStatus();
        // 如果设置了主key参数，进行设值
        if (param.getIsPrimary() != null) {
            accessKey.isPrimary = param.getIsPrimary();
        }
        client.akskUpdate(accessKey);
        // 记录accessKey的修改事件，用于accessKey缓存的更新
        client.iamChangeEventInsert(new IamChangeEvent(ChangeType.ACCESSKEY, param.getAccountId(), accessKey.accessKey));
    }
    
    /**
     * 判断accessKey是否属于指定用户
     * 没有指定targetUserName则判断是否属于当前用户
     * @param isRoot
     * @param targetUserName
     * @param currentUserName
     * @param accessKey
     * @return
     */
    private static boolean userHasTheAccessKey(String targetUserName, ActionParameter param, AkSkMeta accessKey) {
        // accessKeyId的ownerId和当前请求的ownerId不一致
        if (param.currentOwner.getId() != accessKey.ownerId) {
            return false;
        }
        String userName = targetUserName;
        if (targetUserName == null) {
            if (param.isRoot()) {
                userName = null;
            } else {
                userName = param.currentAccessKey.userName;
            }
        }
        // 操作根用户AK，必须是根用户
        if (userName == null && accessKey.isRoot == 1) {
            return true;
        }
        // 操作子用户AK，用户名必须和操作的AK一致
        if (userName != null && userName.equalsIgnoreCase(accessKey.userName)) {
            return true;
        }
        return false;
    }

    /**
     * deleteAccessKey接口，删除AccessKey
     * @param param
     * @throws Exception
     */
    public static void deleteAccessKey(DeleteAccessKeyParam param) throws Exception {
        // 指定用户不存在
        if (param.userName != null && !HBaseUtils.exist(param.getUserParam())) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        // 获取AK
        AkSkMeta accessKey = new AkSkMeta(param.accessKeyId);
        boolean exist = client.akskSelect(accessKey);
        // 如果修改的AK不属于指定的用户
        if (!exist || !userHasTheAccessKey(param.userName, param, accessKey)) {
            throw ExceptionUtils.newNoSuchAccessKeyException(param.accessKeyId);
        }

        // 如果是子用户，删除子用户的AccessKey关联
        if (accessKey.isRoot != 1) {
            User akUser = new User();
            akUser.accountId = param.getAccountId();
            akUser.userName = accessKey.userName;
            User user = HBaseUtils.get(akUser);
            // 不能删除子用户的内建ak
            if (param.accessKeyId.equals(user.builtInAccessKey)) {
                IAMErrorMessage errorMessage = new IAMErrorMessage("deleteBuiltInKey", "This is the built in access key, can not be deleted. ", accessKey.accessKey);
                throw new IAMException(409, "DeleteConflict", errorMessage);
            }
            // 删除AK
            client.akskDelete(accessKey);
            akUser.accessKeys = user.accessKeys;
            if (akUser.accessKeys != null) {
                String oldAccessKeyIds = JSONUtils.toJSONArray(user.accessKeys);
                // 删除对应AK ID
                akUser.accessKeys.remove(param.accessKeyId);
                // 更新用户AK ID列表
                updateUserAccessKeyIds(akUser, oldAccessKeyIds);
            }
        } else {
            // 不能删除根用户的内建ak
            if (accessKey.builtIn == 1) {
                IAMErrorMessage errorMessage = new IAMErrorMessage("deleteBuiltInKey", "This is the built in access key, can not be deleted. ", accessKey.accessKey);
                throw new IAMException(409, "DeleteConflict", errorMessage);
            }
            // 删除AK
            client.akskDelete(accessKey);
            // 如果删除的是根用户AK，根用户AK数量减1
            client.ownerUpdateCurrentAKNum(param.currentOwner, false);
        }
        // 记录accessKey的修改事件，用于accessKey缓存的更新
        client.iamChangeEventInsert(new IamChangeEvent(ChangeType.ACCESSKEY, param.getAccountId(), accessKey.accessKey));
    }
    
    /**
     * listAccessKeys接口
     * 返回有关与指定IAM用户关联的访问密钥ID的信息
     * @param param
     * @return
     * @throws Exception
     */
    public static ListAccessKeysResult listAccessKeys(ListAccessKeysParam param) throws Exception {
        
        if (param.isRoot() && param.userName == null) {
            // 查询根用户的AK，多查询一个判断分页
            AkSkMeta asKey = new AkSkMeta(param.currentOwner.getId());
            List<AkSkMeta> accessKeys = client.akskSelectAll(asKey, param.marker, param.maxItems + 1);
            String userName = param.currentOwner.getName();
            if (accessKeys.size() > param.maxItems) {
                String marker = accessKeys.get(param.maxItems).accessKey;
                accessKeys.remove(param.maxItems.intValue());
                return new ListAccessKeysResult(true, marker, userName, accessKeys, param.isFromConsole);
            } else {
                return new ListAccessKeysResult(false, null, userName, accessKeys, param.isFromConsole);
            }
        } else {
            // 查询子用户AK
            User akUser = HBaseUtils.get(param.getUserParam());
            // 没有找到用户
            if (akUser == null) {
                throw ExceptionUtils.newNoSuchUserException(param.userName);
            }
            if (akUser.accessKeys == null || akUser.accessKeys.size() == 0) {
                return new ListAccessKeysResult(akUser.userName);
            }
            // 待查询的key
            List<String> keys = null;
            boolean isTruncated = false;
            String marker = null;
            // 分页开始位置
            int fromIndex = 0;
            if (param.marker != null) {
                for (int i = 0; i < akUser.accessKeys.size(); i++) {
                    String key = akUser.accessKeys.get(i);
                    if (param.marker.equals(key)) {
                        fromIndex = i;
                        break;
                    }
                }
            }
            // 分页结束位置
            int toIndex = fromIndex + param.maxItems;
            if (toIndex >= akUser.accessKeys.size()) {
                // 无后续分页
                keys = akUser.accessKeys.subList(fromIndex, akUser.accessKeys.size());
            } else {
                // 有后续分页
                keys = akUser.accessKeys.subList(fromIndex, toIndex);
                isTruncated = true;
                marker = akUser.accessKeys.get(toIndex);
            }
            // 批量查询accessKey
            List<AkSkMeta> accessKeys = client.akskList(keys);
            return new ListAccessKeysResult(isTruncated, marker, param.getUserName(), accessKeys, param.isFromConsole);
        }
    }
    
    
    /**
     * 检索有关上次使用指定访问密钥的时间的信息
     * AK被使用时，定时更新serviceName和lastUsedDate，暂时先不实现该功能
     * @param param
     * @return
     * @throws IOException 
     * @throws BaseException 
     */
//    public static GetAccessKeyLastUsedResult getAccessKeyLastUsed(GetAccessKeyLastUsedParam param) throws IOException, BaseException {
//        AkSkMeta aksk = new AkSkMeta();
//        aksk.accessKey = param.accessKeyId;
//        boolean exist = client.akskSelectWithoutCache(aksk);
//        // 如果AK不存在
//        if (!exist || param.currentOwner.getId() != aksk.ownerId) {
//            // 获取用户的ARN
//            String userArn = "";
//            User user = new User();
//            user.accountId = param.getAccountId();
//            user.userName = param.currentAccessKey.userName;
//            if (param.isRoot()) {
//                userArn = user.getRootArn();
//            } else {
//                user = HBaseUtils.get(user);
//                userArn = user.getArn();
//            }
//            throw new BaseException(403, "AccessDenied", "User: " + userArn + " is not authorized to perform iam:GetAccessKeyLastUsed on resource: access key " + param.accessKeyId + ".");
//        }
//        // 组织返回结果
//        GetAccessKeyLastUsedResult result = new GetAccessKeyLastUsedResult();
//        result.userName = aksk.userName;
//        result.accessKeyLastUsed.lastUsedDate = aksk.lastUsedDate == 0 ? null : DateUtils.format(aksk.lastUsedDate);
//        result.accessKeyLastUsed.serviceName = StringUtils.isEmpty(aksk.serviceName) ? "N/A" : aksk.serviceName;
//        return result;
//    }
    
    /**
     * 兼容原有listAccessKey接口，原有接口名称少了一个字母's'
     */
    public static ListAccessKeysResult listAccessKey(ListAccessKeysParam param) throws Exception {
        return listAccessKeys(param);
    }
    
}
