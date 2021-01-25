package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.entity.GroupPolicy;
import cn.ctyun.oos.iam.server.util.ValidationUtils;

/**
 * 列出附加到指定IAM组的所有托管策略参数
 * @author wangduo
 *
 */
public class ListAttachedGroupPoliciesParam extends ActionParameter {

    public String groupName;
    public String marker;
    public Integer maxItems = 100;
    
    @Override
    public void validate() {
        ValidationUtils.validateGroupName(groupName, errorMessages);
        ValidationUtils.validateMarker(marker, errorMessages);
        ValidationUtils.validateMaxItems(maxItems, errorMessages);
    }
    
    public GroupPolicy getGroupPolicy() {
        GroupPolicy groupPolicy = new GroupPolicy();
        groupPolicy.accountId = getAccountId();
        groupPolicy.groupName = groupName;
        return groupPolicy;
    }
    
    /**
     * 查询组参数
     * @return
     */
    public Group getGroupParam() {
        Group group = new Group();
        group.accountId = getAccountId();
        group.groupName = groupName;
        return group;
    }
    
    public String getResource() {
        return groupName;
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generateGroupArn(getAccountId(), groupName);
    }
}
