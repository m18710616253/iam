package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.util.ValidationUtils;

/**
 * 获取用户的MFA请求参数
 * @author wangduo
 *
 */
public class ListMFADevicesParam extends ActionParameter {

    public String userName;
    public String marker;
    public Integer maxItems = 100;
    
    @Override
    public void validate() {
        if (userName != null) {
            ValidationUtils.validateUserName(userName, errorMessages);
        }
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
}
