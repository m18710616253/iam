package cn.ctyun.oos.iam.server.internal.api;

/**
 * 列出账户中可用的所有策略参数
 * @author wangduo
 *
 */
public class ListOOSPoliciesParam {

    public String marker;
    public Integer maxItems = 100;
    public String policyName;
}
