package cn.ctyun.oos.iam.server.result;

/**
 * 检索有关上次使用指定访问密钥的时间的信息
 * @author wangduo
 *
 */
public class GetAccessKeyLastUsedResult extends Result {

    public String userName;
    public AccessKeyLastUsed accessKeyLastUsed = new AccessKeyLastUsed();
    
    public class AccessKeyLastUsed {
        public String lastUsedDate;
        public String serviceName;
    }
}
