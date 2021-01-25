package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 获取IAM组及组的IAM用户列表参数
 * @author wangduo
 *
 */
public class GetGroupParam extends ActionParameter {

    public String marker;
    public Integer maxItems = 100;
    public String groupName;

    @Override
    public void validate() {
        ValidationUtils.validateMarker(marker, errorMessages);
        // maxItems 1-1000
        ValidationUtils.validateMaxItems(maxItems, errorMessages);
        ValidationUtils.validateGroupName(groupName, errorMessages);
    }

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
    
    /**
     * 返回日志审计记录的ARN
     * @return
     */
    @Override
    public List<Resources> getTrailResources() {
        List<Resources> resources = new ArrayList<>();
        resources.add(ResourcesUtils.generateGroupResources(getAccountId(), groupName));
        return resources;
    }
}
