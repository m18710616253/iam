package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 删除指定IAM用户的密码
 * @author wangduo
 *
 */
public class DeleteLoginProfileParam extends ActionParameter {

    public String userName;
    
    @Override
    public void validate() {
        ValidationUtils.validateUserName(userName, errorMessages);
    }

    public User getUser() {
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
    
    /**
     * 返回日志审计记录的ARN
     * @return
     */
    @Override
    public List<Resources> getTrailResources() {
        List<Resources> resources = new ArrayList<>();
        resources.add(ResourcesUtils.generateUserResources(getAccountId(), userName));
        return resources;
    }
}
