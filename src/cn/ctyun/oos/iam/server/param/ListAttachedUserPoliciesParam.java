package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.entity.UserPolicy;
import cn.ctyun.oos.iam.server.util.ValidationUtils;

/**
 * 列出附加到指定IAM用户的所有托管策略参数
 * @author wangduo
 *
 */
public class ListAttachedUserPoliciesParam extends ActionParameter {

    public String userName;
    public String marker;
    public Integer maxItems = 100;
    
    @Override
    public void validate() {
        ValidationUtils.validateUserName(userName, errorMessages);
        ValidationUtils.validateMaxItems(maxItems, errorMessages);
        ValidationUtils.validateMarker(marker, errorMessages);
    }
    
    public UserPolicy getUserPolicy() {
        UserPolicy userPolicy = new UserPolicy();
        userPolicy.accountId = getAccountId();
        userPolicy.userName = userName;
        return userPolicy;
    }
    
    /**
     * 查询user参数
     * @return
     */
    public User getUserParam() {
        User user = new User();
        user.accountId = getAccountId();
        user.userName = userName;
        return user;
    }
    
    public String getResource() {
        return userName;
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generateUserArn(getAccountId(), userName);
    }
}
