package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.util.ValidationUtils;

/**
 * 组列表参数
 * @author wangduo
 *
 */
public class ListGroupsParam extends ActionParameter {

    public String marker;
    public Integer maxItems = 100;
    /** 组名称模糊匹配 */
    public String groupName;

    @Override
    public void validate() {
        ValidationUtils.validateMarker(marker, errorMessages);
        ValidationUtils.validateMaxItems(maxItems, errorMessages);
        if (groupName != null) {
            ValidationUtils.validateGroupName(groupName, errorMessages);
        }
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generateGroupArn(getAccountId(), "*");
    }

}
