package cn.ctyun.oos.iam.server.param;

import org.apache.commons.lang.StringUtils;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.util.ValidationUtils;

/**
 * AccessKey列表查询参数
 * @author wangduo
 *
 */
public class ListAccessKeysParam extends ActionParameter {

    public String marker;
    public Integer maxItems = 100;
    public String userName;

    @Override
    public void validate() {
        ValidationUtils.validateMarker(marker, errorMessages);
        ValidationUtils.validateMaxItems(maxItems, errorMessages);
        if (userName != null) {
            ValidationUtils.validateUserName(userName, errorMessages);
        }
    }

    /**
     * 查询user参数
     * @return
     */
    public User getUserParam() {
        User user = new User();
        user.accountId = getAccountId();
        user.userName = getUserName();
        return user;
    }
    
    public String getUserName() {
        // 没有输入用户名，使用自身的用户名
        if (StringUtils.isBlank(userName)) {
            return this.currentAccessKey.userName;
        } else {
            return userName;
        }
    }
    
    public String getResource() {
        if (isRoot() && userName == null) {
            return currentOwner.name;
        } else {
            return getUserName();
        }
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generateUserArn(getAccountId(), getUserName());
    }
}
