package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 创建用户AK参数
 * @author wangduo
 *
 */
public class CreateAccessKeyParam extends ActionParameter {

    /** 用户名，未指定则为自己 */
    public String userName;

    @Override
    public void validate() {
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
    
    private String getUserName() {
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
    
    /**
     * 返回日志审计记录的ARN
     * @return
     */
    @Override
    public List<Resources> getTrailResources() {
        List<Resources> resources = new ArrayList<>();
        if (isRoot() && userName == null) {
            resources.add(ResourcesUtils.generateRootUserResources(getAccountId()));
        } else {
            resources.add(ResourcesUtils.generateUserResources(getAccountId(), getUserName()));
        }
        return resources;
    }
}
