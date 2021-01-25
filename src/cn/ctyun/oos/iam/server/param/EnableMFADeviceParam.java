package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 启用指定的MFA设备请求参数
 * @author wangduo
 *
 */
public class EnableMFADeviceParam extends ActionParameter {

    public String authenticationCode1;
    public String authenticationCode2;
    public String serialNumber;
    public String userName;
    
    @Override
    public void validate() {
        ValidationUtils.validateMFACode("authenticationCode1", authenticationCode1, errorMessages);
        ValidationUtils.validateMFACode("authenticationCode2", authenticationCode2, errorMessages);
        ValidationUtils.validateMFASerialNumber(serialNumber, errorMessages);
        ValidationUtils.validateUserName(userName, errorMessages);
    }

    public String getResource() {
        return userName;
    }
    
    public User getUser() {
        User user = new User();
        user.accountId = getAccountId();
        user.userName = userName;
        return user;
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generateUserArn(getAccountId(), userName);
    }
    
    /**
     * 返回日志审计记录的ARN
     * @return
     */
    @Override
    public List<Resources> getTrailResources() {
        List<Resources> resources = new ArrayList<>();
        resources.add(ResourcesUtils.generateUserResources(getAccountId(), userName));
        resources.add(ResourcesUtils.generateMfaDeviceResources(serialNumber));
        return resources;
    }
}
