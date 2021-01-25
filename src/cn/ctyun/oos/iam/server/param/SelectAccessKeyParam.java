package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.server.action.ActionParameter;

/**
 * 获取SecretKey的参数
 * @author wangduo
 *
 */
public class SelectAccessKeyParam extends ActionParameter {

    public String ak;
    
    @Override
    public void validate() {
    }
    
}
