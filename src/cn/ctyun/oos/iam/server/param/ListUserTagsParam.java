package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.util.ValidationUtils;

/**
 * 用户标签列表参数
 * @author wangduo
 *
 */
public class ListUserTagsParam extends ActionParameter {

    public String marker;
    public Integer maxItems = 100;
    public String userName;

    @Override
    public void validate() {
        ValidationUtils.validateMarker(marker, errorMessages);
        ValidationUtils.validateMaxItems(maxItems, errorMessages);
        ValidationUtils.validateUserName(userName, errorMessages);
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
