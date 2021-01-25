package cn.ctyun.oos.iam.accesscontroller.service;

import java.io.IOException;
import java.util.List;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;

/**
 * 获取policy的接口
 * @author wangduo
 *
 */
public interface PolicyService {

    /**
     * 获取用户访问控制策略列表
     * @param accountId
     * @param userName
     * @return
     * @throws IOException 获取数据异常
     * @throws BaseException 
     */
    List<AccessPolicy> getUserPolicies(String accountId, String userName) throws IOException, BaseException;
}
