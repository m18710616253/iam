package cn.ctyun.oos.iam.accesscontroller.policy;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.policy.reader.JsonPolicyReader;

/**
 * 访问控制策略
 * 对策略的JSON内容进行解析，转换为策略对象
 * @author wangduo
 *
 */
public class AccessPolicy {

    public static final String DEFAULT_POLICY_VERSION = "2012-10-17";

    public String id;
    public String version = DEFAULT_POLICY_VERSION;
    public List<Statement> statements = new ArrayList<Statement>();
    
    /** policy的初始json，调试使用 */
    public String jsonString;
    
    /**
     * 解析policy json
     * @param jsonString
     * @return
     * @throws PolicyParseException
     */
    public static AccessPolicy fromJson(String jsonString) throws PolicyParseException {
        return new JsonPolicyReader().createPolicyFromJsonString(jsonString);
    }
    
    public static void main(String[] args) {
        String json ="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"NotAction\":[\"oos:ListAllMyBuckets\",\"oos:GetBucketLocation\"],\"Resource\":\"arn:ctyun:oos:::*\"},{\"Effect\":\"Allow\",\"Action\":\"oos:ListBucket\",\"Resource\":\"arn:ctyun:oos:::BUCKET-NAME\",\"Condition\":{\"StringLike\":{\"oos:prefix\":[\"\",\"home/\",\"home/${ctyun:username}/\"]}}},{\"Effect\":\"Allow\",\"Action\":\"oos:*\",\"Resource\":[\"arn:ctyun:oos:::BUCKET-NAME/home/${ctyun:username}\",\"arn:ctyun:oos:::BUCKET-NAME/home/${ctyun:username}/*\"]}]}";
        AccessPolicy policy;
        try {
            policy = fromJson(json);
            System.out.println(policy);
        } catch (PolicyParseException e) {
            System.out.println(e.getMessage());
        }
        
    }

}
