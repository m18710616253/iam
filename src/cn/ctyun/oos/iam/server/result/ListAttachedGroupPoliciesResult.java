package cn.ctyun.oos.iam.server.result;

import java.util.List;

/**
 * 列出附加到指定IAM组的所有托管策略结果
 * 
 * @author wangduo
 *
 */
public class ListAttachedGroupPoliciesResult extends Result {

    public List<AttachedPolicy> attachedPolicies;
    public Boolean isTruncated;
    public String marker;
    public Long total;
    
}
