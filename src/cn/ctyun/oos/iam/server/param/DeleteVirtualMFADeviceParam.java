package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 删除虚拟MFA设备
 * @author wangduo
 *
 */
public class DeleteVirtualMFADeviceParam extends ActionParameter {

    public String serialNumber;
    
    @Override
    public void validate() {
        ValidationUtils.validateMFASerialNumber(serialNumber, errorMessages);
    }
    
    @Override
    public String getResourceArn() {
        return serialNumber;
    }

    /**
     * 返回日志审计记录的ARN
     * @return
     */
    @Override
    public List<Resources> getTrailResources() {
        List<Resources> resources = new ArrayList<>();
        resources.add(ResourcesUtils.generateMfaDeviceResources(serialNumber));
        return resources;
    }
}
