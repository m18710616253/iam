package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.Tag;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.util.Tags;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 创建用户请求参数
 * @author wangduo
 *
 */
public class CreateUserParam extends ActionParameter {

    public String userName;
    public List<Tag> tags;
    
    // http://localhost:9097/?Action=CreateUser&UserName=test&Tags.member.1.Key=testkey&Tags.member.1.value=testvalue
    /**
     * 请求参数解析
     * 用户标签需要单独处理
     * @throws BaseException 
     */
    @Override
    public void parseParams() throws BaseException {
       tags = Tags.parse(requestParams, errorMessages);
     }
    
    /**
     * 参数校验
     */
    @Override
    public void validate() {
        // 校验用户名
       ValidationUtils.validateUserName(userName, errorMessages);
    }

    /**
     * 使用请求参数创建User
     * @return
     */
    public User getUser() {
        User user = new User();
        user.userId = IAMStringUtils.generateId();
        user.accountId = getAccountId();
        user.userName = userName;
        user.tags = tags;
        user.createDate = System.currentTimeMillis();
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
