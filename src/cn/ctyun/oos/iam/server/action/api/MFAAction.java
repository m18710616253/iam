package cn.ctyun.oos.iam.server.action.api;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.filter.BinaryComparator;
import org.apache.hadoop.hbase.filter.CompareFilter.CompareOp;
import org.apache.hadoop.hbase.filter.SingleColumnValueFilter;
import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.iam.accesscontroller.util.ExceptionUtils;
import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;
import cn.ctyun.oos.iam.accesscontroller.util.IAMException;
import cn.ctyun.oos.iam.server.action.Action;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.entity.MFADevice;
import cn.ctyun.oos.iam.server.entity.ParseArnException;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.entity.UserMFADevice;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.param.AssignmentStatusType;
import cn.ctyun.oos.iam.server.param.CreateVirtualMFADeviceParam;
import cn.ctyun.oos.iam.server.param.DeactivateMFADeviceParam;
import cn.ctyun.oos.iam.server.param.DeleteVirtualMFADeviceParam;
import cn.ctyun.oos.iam.server.param.EnableMFADeviceParam;
import cn.ctyun.oos.iam.server.param.ListMFADevicesParam;
import cn.ctyun.oos.iam.server.param.ListVirtualMFADevicesParam;
import cn.ctyun.oos.iam.server.param.UserType;
import cn.ctyun.oos.iam.server.result.CreateVirtualMFADeviceResult;
import cn.ctyun.oos.iam.server.result.ListMFADevicesResult;
import cn.ctyun.oos.iam.server.result.ListVirtualMFADevicesResult;
import cn.ctyun.oos.iam.server.result.PageResult;
import cn.ctyun.oos.iam.server.service.AccountSummaryService;
import cn.ctyun.oos.iam.server.util.MFAAuthenticator;

/**
 * MFA设备接口
 * 
 * @author wangduo
 *
 */
@Action
public class MFAAction {

    private static final Log log = LogFactory.getLog(MFAAction.class);
    
    /**
     * 创建新的虚拟MFA设备
     * data:image/png;base64,
     * @param param
     * @return
     * @throws Exception 
     */
    public static CreateVirtualMFADeviceResult createVirtualMFADevice(CreateVirtualMFADeviceParam param) throws Exception {
        
        // 如果请求来自于用户控制台访问
        if (param.isFromConsole) {
            // 如果有同名MFA设备创建且未绑定，直接使用该设备进行返回
            MFADevice mfaDevice = new MFADevice();
            mfaDevice.accountId = param.getAccountId();
            mfaDevice.virtualMFADeviceName = param.virtualMFADeviceName;
            mfaDevice = HBaseUtils.get(mfaDevice);
            if (mfaDevice != null && AssignmentStatusType.Unassigned.value.equals(mfaDevice.status)) {
                return new CreateVirtualMFADeviceResult(param.getAccountId(), mfaDevice);
            }
        }
        
        // 获取当前账户的使用及配额信息
        AccountSummary accountSummary = AccountSummaryService.getAccountSummary(param.getAccountId());
        // 账户中的虚拟MFA设备数量：账户的用户数 + 1
        if (accountSummary.mFADevices >= accountSummary.users + 1) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("mfaDevicesQuota", 
                    "Cannot exceed quota for MFADevices: %s.", accountSummary.users + 1);
            throw new IAMException(409, "LimitExceeded", errorMessage);
        }
        
        MFADevice mFADevice = param.generateMFADevice();
        boolean created = HBaseUtils.checkAndCreate(mFADevice);
        if (created) {
            // 账户虚拟MFA设备数量加1
            AccountSummaryService.increment(param.getAccountId(), AccountSummary.MFA_DEVICES, 1);
        } else {
            IAMErrorMessage errorMessage = new IAMErrorMessage("mfaDeviceAlreadyExists", "MFADevice entity at the same path and name already exists.");
            throw new IAMException(409, "EntityAlreadyExists", errorMessage);
        }
        return new CreateVirtualMFADeviceResult(param.getAccountId(), mFADevice);
    }

    /**
     * 删除虚拟MFA设备
     * @param param
     * @throws IOException 
     * @throws BaseException 
     */
    public static void deleteVirtualMFADevice(DeleteVirtualMFADeviceParam param) throws BaseException, IOException {
        MFADevice mFADevice = getMFADeviceFromArn(param.serialNumber, param.getAccountId()); 
        // 如果MFA已被人使用，root用户没有设置userName，使用userType进行判断
        if (!StringUtils.isEmpty(mFADevice.userType)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("mfaDeviceInUse", "MFA VirtualDevice in use. Must deactivate first.");
            throw new IAMException(409, "DeleteConflict", errorMessage);
        }
        boolean deleted = HBaseUtils.checkAndDelete(mFADevice);
        if (deleted) {
            // 账户虚拟MFA设备数量减1
            AccountSummaryService.increment(param.getAccountId(), AccountSummary.MFA_DEVICES, -1);
        } else {
            throw ExceptionUtils.newNoSuchMFADeviceException(param.serialNumber);
        }
        
    }


    /**
     * 启用指定的MFA设备并将其与指定的IAM用户关联
     * @param param
     * @throws IOException 
     * @throws BaseException 
     */
    public static void enableMFADevice(EnableMFADeviceParam param) throws BaseException, IOException {
        
        User existUser = HBaseUtils.get(param.getUser());
        // 验证子用户是否存在
        if (existUser == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        MFADevice mFADevice = getMFADeviceFromArn(param.serialNumber, param.getAccountId());
        // 如果MFA已被人使用，root用户没有设置userName，使用userType进行判断
        if (!StringUtils.isEmpty(mFADevice.userType)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("mfaDeviceAlreadyInUse", "MFA Device is already in use.");
            throw new IAMException(409, "EntityAlreadyExists", errorMessage);
        }
        // 验证两个验证码连续且正确
        if (!MFAAuthenticator.checkCode(mFADevice.base32StringSeed, Long.valueOf(param.authenticationCode1), 
                Long.valueOf(param.authenticationCode2))) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("authenticationCodeInvalid", "Authentication code for device is not valid.");
            throw new IAMException(403, "InvalidAuthenticationCode", errorMessage);
        }

        // 创建用户和MFA设备关系
        UserMFADevice userMFADevice = new UserMFADevice();
        userMFADevice.userType = UserType.User.value;
        userMFADevice.accountId = existUser.accountId;
        // userName传参时忽略大小写，使用子用户自身的UserName
        userMFADevice.userName = existUser.userName;
        userMFADevice.virtualMFADeviceName = mFADevice.virtualMFADeviceName;
        // 保存用户和MFA的关系
        boolean created = HBaseUtils.checkAndCreate(userMFADevice);
        if (created) {
            // 增加账户中在使用的MFA的数量
            AccountSummaryService.increment(param.getAccountId(), AccountSummary.MFA_DEVICES_IN_USE, 1);
        } else {
            IAMErrorMessage errorMessage = new IAMErrorMessage("mfaDevicesPerUserQuota", "Cannot exceed quota limit for MFADevicesPerUser.");
            throw new IAMException(409, "LimitExceeded", errorMessage);
        }
        // 修改MFA的所属
        mFADevice.userType = UserType.User.value;
        mFADevice.userName = existUser.userName;
        mFADevice.status = AssignmentStatusType.Assigned.value;
        mFADevice.enableDate = System.currentTimeMillis();
        HBaseUtils.put(mFADevice);
        // 更新用户
        User user = new User();
        user.accountId = existUser.accountId;
        user.userName = existUser.userName;
        user.mFAName = mFADevice.virtualMFADeviceName;
        HBaseUtils.put(user);
    }

    /**
     * 禁用指定的MFA设备，并与用户解除关联
     * @param param
     * @throws BaseException 
     * @throws IOException 
     */
    public static void deactivateMFADevice(DeactivateMFADeviceParam param) throws IOException, BaseException {
        User existUser = HBaseUtils.get(param.getUser());
        // 验证子用户是否存在
        if (existUser == null) {
            throw ExceptionUtils.newNoSuchUserException(param.userName);
        }
        MFADevice mFADevice = getMFADeviceFromArn(param.serialNumber, param.getAccountId());
        // 如果MFA没有被使用
        if (StringUtils.isEmpty(mFADevice.userType)) {
            throw ExceptionUtils.newMFADeviceInvalidForUserException();
        }
        // 获取用户的MFA信息
        UserMFADevice userMFADevice = new UserMFADevice();
        userMFADevice.accountId = existUser.accountId;
        // userName传参时忽略大小写，使用子用户自身的UserName
        userMFADevice.userName = existUser.userName;
        userMFADevice = HBaseUtils.get(userMFADevice);
        // 用户没有MFA设备
        if (userMFADevice == null) {
            throw ExceptionUtils.newMFADeviceInvalidForUserException();
        }
        // 参数中的MFA设备与用户的MFA设备不同
        if (!Bytes.equals(userMFADevice.getMFADevice().getRowKey(), mFADevice.getRowKey())) {
            throw ExceptionUtils.newMFADeviceInvalidForUserException();
        }
        boolean deleted = HBaseUtils.checkAndDelete(userMFADevice);
        if (deleted) {
            // 减少账户中在使用的MFA的数量
            AccountSummaryService.increment(param.getAccountId(), AccountSummary.MFA_DEVICES_IN_USE, -1);
        }
        mFADevice.userType = "";
        mFADevice.userName = "";
        mFADevice.status = AssignmentStatusType.Unassigned.value;
        HBaseUtils.put(mFADevice);
        // 更新用户
        User user = new User();
        user.accountId = existUser.accountId;
        user.userName = existUser.userName;
        user.mFAName = "";
        HBaseUtils.put(user);
    }

    /**
     * 按分配状态列出AWS账户中定义的虚拟MFA设备
     * @param param
     * @return
     * @throws Throwable 
     */
    public static ListVirtualMFADevicesResult listVirtualMFADevices(ListVirtualMFADevicesParam param) throws Throwable {
        
        Scan scan = HBaseUtils.buildScan(param.getAccountId(), param.marker);
        // 分配状态查询
        if (AssignmentStatusType.Assigned.value.equals(param.assignmentStatus) 
                || AssignmentStatusType.Unassigned.value.equals(param.assignmentStatus) ) {
            SingleColumnValueFilter assignedFilter = new SingleColumnValueFilter(Bytes.toBytes(Qualifier.DEFAULT_FAMILY), 
                    Bytes.toBytes(MFADevice.QUALIFIER_STATUS), CompareOp.EQUAL, new BinaryComparator(Bytes.toBytes(param.assignmentStatus)));
            scan.setFilter(assignedFilter);
        }
        // 当marker为空，并且请求来自于proxy时获取数据总数
        boolean getTotal = param.marker == null && param.isFromConsole;
        // 查询MFA列表
        PageResult<MFADevice> pageResult = HBaseUtils.scan(scan, param.maxItems, MFADevice.class, getTotal);
        
        // 获取MFA用户信息
        List<byte[]> userRowKeys = new ArrayList<>();
        for (MFADevice mFADevice : pageResult.list) {
            if (StringUtils.isEmpty(mFADevice.userName)) {
                continue;
            }
            userRowKeys.add(mFADevice.getUser().getRowKey());
        }
        // 批量获取用户数据
        List<User> users = HBaseUtils.get(userRowKeys, User.class);
        ListVirtualMFADevicesResult result = new ListVirtualMFADevicesResult(pageResult, users);
        return result;
    }
    
    /**
     * 获取用户的MFA，如果没有指定用户则获取当前用户的MFA
     * @param param
     * @return
     * @throws IOException 
     * @throws BaseException 
     */
    public static ListMFADevicesResult listMFADevices(ListMFADevicesParam param) throws IOException, BaseException {
        
        UserMFADevice userMFADevice = new UserMFADevice();
        // 有用户名参数，查询子用户
        if (param.userName != null) {
            User existUser = HBaseUtils.get(param.getUser());
            // 验证子用户是否存在
            if (existUser == null) {
                throw ExceptionUtils.newNoSuchUserException(param.userName);
            }
            userMFADevice.userName = existUser.userName;
        } else {
            // 如果是根用户
            if (param.isRoot()) {
                // 返回空结果
                return new ListMFADevicesResult();
            }
            userMFADevice.userName = param.currentAccessKey.userName;
        }
        userMFADevice.userType = UserType.User.value;
        userMFADevice.accountId = param.getAccountId();
        
        userMFADevice = HBaseUtils.get(userMFADevice);
        if (userMFADevice == null) {
            return new ListMFADevicesResult();
        }
        MFADevice mFADevice = HBaseUtils.get(userMFADevice.getMFADevice());
        return new ListMFADevicesResult(mFADevice);
    }
    
    /**
     * 通过arn获取MFADevice
     * @param arn
     * @return
     * @throws BaseException
     * @throws IOException
     */
    private static MFADevice getMFADeviceFromArn(String arn, String accountId) throws BaseException, IOException {
        MFADevice mFADevice = new MFADevice();
        try {
            mFADevice.parseArn(arn);
        } catch (ParseArnException e) {
            log.error("ARN " + arn + " is not valid.", e);
            IAMErrorMessage errorMessage = new IAMErrorMessage("arnInvalid", "ARN %s is not valid.", arn);
            throw new IAMException(400, "InvalidInput", errorMessage);
        }
        // 查询MFA设备数据
        MFADevice existMFA = HBaseUtils.get(mFADevice);
        if (existMFA == null || !mFADevice.accountId.equals(accountId)) {
            throw ExceptionUtils.newNoSuchMFADeviceException(arn);
        }
        return existMFA;
    }
    
}
