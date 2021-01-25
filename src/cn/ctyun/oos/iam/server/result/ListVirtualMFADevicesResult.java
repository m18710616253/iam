package cn.ctyun.oos.iam.server.result;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import cn.ctyun.oos.iam.server.entity.MFADevice;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.param.UserType;

/**
 * 按分配状态列出AWS账户中定义的虚拟MFA设备返回结果
 * @author wangduo
 *
 */
public class ListVirtualMFADevicesResult extends Result {

    public List<VirtualMFADevice> virtualMFADevices = new ArrayList<>();
    public Boolean isTruncated;
    public String marker;
    public Long total;
    
    public ListVirtualMFADevicesResult(PageResult<MFADevice> pageResult, List<User> users) {
        Map<String, User> userMap = new HashMap<>();
        for (User user : users) {
            userMap.put(user.userName, user);
        }
        
        for (MFADevice mFADevice : pageResult.list) {
            // 设置虚拟设备信息
            VirtualMFADevice virtualMFADevice = new VirtualMFADevice();
            virtualMFADevice.serialNumber = mFADevice.getArn();
            virtualMFADevice.enableDate = mFADevice.enableDate;
            
            // 如果MFA的使用者是根用户
            if (UserType.Root.value.equals(mFADevice.userType)) {
                User user = new User();
                user.accountId = mFADevice.accountId;
                virtualMFADevice.user.userId = user.accountId;
                virtualMFADevice.user.arn = user.getRootArn();
                virtualMFADevice.user.passwordLastUsed = 0L;
                virtualMFADevice.user.createDate = 0L;
                continue;
            }
            
            // 设置虚拟设备的用户信息
            if (StringUtils.isNotEmpty(mFADevice.userName)) {
                User user = userMap.get(mFADevice.userName);
                if (user == null) {
                    continue;
                }
                virtualMFADevice.user.userName = user.userName;
                virtualMFADevice.user.userId = user.userId;
                virtualMFADevice.user.arn = user.getArn();
                virtualMFADevice.user.passwordLastUsed = user.passwordLastUsed;
                virtualMFADevice.user.createDate = user.createDate;
            }
            
            virtualMFADevices.add(virtualMFADevice);
        }
        this.isTruncated = pageResult.isTruncated;
        this.marker = pageResult.marker;
        this.total = pageResult.total;
    }
    
}
