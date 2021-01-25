package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.MFADevice;
import cn.ctyun.oos.iam.server.util.MFAAuthenticator;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 创建新的虚拟MFA设备请求参数
 * @author wangduo
 *
 */
public class CreateVirtualMFADeviceParam extends ActionParameter {

    public String virtualMFADeviceName;
    
    @Override
    public void validate() {
        ValidationUtils.validateVirtualMFADeviceName(virtualMFADeviceName, errorMessages);
    }

    /**
     * 生成一个MFA虚拟设备
     * @return
     */
    public MFADevice generateMFADevice() {
        MFADevice mfaDevice = new MFADevice();
        mfaDevice.accountId = getAccountId();
        mfaDevice.virtualMFADeviceName = virtualMFADeviceName;
        mfaDevice.status = AssignmentStatusType.Unassigned.value;
        mfaDevice.serialNumber = mfaDevice.getArn();
        mfaDevice.base32StringSeed = MFAAuthenticator.generateBase32StringSeed();
        mfaDevice.createDate = System.currentTimeMillis();
        return mfaDevice;
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generateMFAArn(getAccountId(), virtualMFADeviceName);
    }

    /**
     * 返回日志审计记录的ARN
     * @return
     */
    @Override
    public List<Resources> getTrailResources() {
        List<Resources> resources = new ArrayList<>();
        resources.add(ResourcesUtils.generateMfaDeviceResources(getAccountId(), virtualMFADeviceName));
        return resources;
    }
}
