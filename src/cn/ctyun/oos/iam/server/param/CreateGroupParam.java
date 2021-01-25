package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 创建组请求参数
 * @author wangduo
 *
 */
public class CreateGroupParam extends ActionParameter {

    public String groupName;
    
    /**
     * 参数校验
     */
    @Override
    public void validate() {
        // 校验用户名
       ValidationUtils.validateGroupName(groupName, errorMessages);
    }

    /**
     * 使用请求参数创建Group
     * @return
     */
    public Group getGroup() {
        Group group = new Group();
        group.groupId = IAMStringUtils.generateId();
        group.accountId = getAccountId();
        group.groupName = groupName;
        group.createDate = System.currentTimeMillis();
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
