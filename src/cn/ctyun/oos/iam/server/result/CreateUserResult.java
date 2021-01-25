package cn.ctyun.oos.iam.server.result;

import cn.ctyun.oos.iam.server.entity.User;

/**
 * CreateUser返回结果
 * @author wangduo
 *
 */
public class CreateUserResult extends Result {

    public User user = new User();
    
    public CreateUserResult(User user) {
        this.user.userName = user.userName;
        this.user.userId = user.userId;
        this.user.tags = user.tags;
        this.user.createDate = user.createDate;
        this.user.arn = user.getArn();
    }
}
