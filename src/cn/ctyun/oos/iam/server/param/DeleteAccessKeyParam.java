package cn.ctyun.oos.iam.server.param;


import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 删除AK请求参数
 * @author wangduo
 *
 */
public class DeleteAccessKeyParam extends ActionParameter {

    public String userName;
    public String accessKeyId;

    @Override
    public void validate() {
        if (userName != null) {
            ValidationUtils.validateUserName(userName, errorMessages);
        }
        ValidationUtils.validateAccessKeyId(accessKeyId, errorMessages);
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
        return accessKeyId;
    }

    
    private String getUserName() {
        // 没有输入用户名，使用自身的用户名
        if (StringUtils.isBlank(userName)) {
            return this.currentAccessKey.userName;
        } else {
            return userName;
        }
    }
    @Override
    public String getResourceArn() {
        return ARNUtils.generateUserArn(getAccountId(), getUserName());
    }
    
    /**
     * 返回日志审计记录的ARN
     * @return
     */
    @Override
    public List<Resources> getTrailResources() {
        List<Resources> resources = new ArrayList<>();
        resources.add(ResourcesUtils.generateAccessKeyResources(accessKeyId));
        if (isRoot() && userName == null) {
            resources.add(ResourcesUtils.generateRootUserResources(getAccountId()));
        } else {
            resources.add(ResourcesUtils.generateUserResources(getAccountId(), getUserName()));
        }
        return resources;
    }

}
