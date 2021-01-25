package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.util.ValidationUtils;

/**
 * 更改当前用户的IAM用户的密码参数
 * @author wangduo
 *
 */
public class ChangePasswordParam extends ActionParameter {

    public String newPassword;
    public String oldPassword;
    
    @Override
    public void validate() {
        ValidationUtils.validatePassword("newPassword", newPassword, errorMessages);
        ValidationUtils.validatePassword("oldPassword", oldPassword, errorMessages);
    }

    @Override
    public String getResourceArn() {
        return ARNUtils.generateUserArn(getAccountId(), currentAccessKey.userName);
    }
    
    @Override
    public String toJson() {
        return null;
    }
}
