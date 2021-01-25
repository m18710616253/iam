package cn.ctyun.oos.iam.server.result;

import cn.ctyun.oos.iam.server.entity.User;

/**
 * GetUser返回结果
 * @author wangduo
 *
 */
public class GetUserResult extends Result {

    public User user = new User();
    
    public GetUserResult(User user) {
        this.user.userName = user.userName;
        this.user.userId = user.userId;
        this.user.tags = user.tags;
        this.user.createDate = user.createDate;
        this.user.passwordLastUsed = user.passwordLastUsed;
        this.user.iPLastUsed = user.iPLastUsed;
        this.user.arn = user.arn;
    }
    
}
