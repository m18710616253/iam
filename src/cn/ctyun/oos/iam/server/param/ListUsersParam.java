package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.util.ValidationUtils;

/**
 * 用户列表参数
 * @author wangduo
 *
 */
public class ListUsersParam extends ActionParameter {

    public String marker;
    public Integer maxItems = 100;
    /** 用户名称模糊匹配 */
    public String userName;
    /** accessKeyId匹配 */
    public String accessKeyId;
    
    @Override
    public void validate() {
        ValidationUtils.validateMarker(marker, errorMessages);
        ValidationUtils.validateMaxItems(maxItems, errorMessages);
        if (userName != null) {
            ValidationUtils.validateUserName(userName, errorMessages);
        }
        if (accessKeyId != null) {
            ValidationUtils.validateAccessKeyIdCond(accessKeyId, errorMessages);
        }
    }

    @Override
    public String getResourceArn() {
        return ARNUtils.generateUserArn(getAccountId(), "*");
    }
}
