package cn.ctyun.oos.iam.server.result;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.metadata.AkSkMeta;

/**
 * AccessKey查询结果
 * @author wangduo
 *
 */
public class ListAccessKeysResult extends Result {

    public List<AccessKeyResult> accessKeyMetadata = new ArrayList<>();
    public boolean isTruncated = false;
    public String marker;
    public String userName;
    
    public ListAccessKeysResult(String userName) {
        this.userName = userName;
    }
    
    public ListAccessKeysResult(boolean isTruncated, String marker, String userName, List<AkSkMeta> accessKeys, boolean fromConsole) {
        this.userName = userName;
        if (accessKeys != null) {
            for (AkSkMeta accessKey : accessKeys) {
                AccessKeyResult accessKeyResult = new AccessKeyResult();
                accessKeyResult.accessKeyId = accessKey.accessKey;
                accessKeyResult.userName = userName;
                accessKeyResult.status = accessKey.status == 1 ? "Active" : "Inactive";
                // 对于老版本创建的ak,显示是否是主key
                if (accessKey.createDate == 0) {
                    accessKeyResult.isPrimary = accessKey.isPrimary == 1 ? "true" : "false";
                }
                accessKeyResult.createDate = accessKey.createDate == 0 ? null : accessKey.createDate;
                // 控制台访问时，对于老版本创建的AK List时可以查看秘钥（上线前创建的AK没有创建时间）
                if (accessKey.createDate == 0 && fromConsole) {
                    accessKeyResult.secretAccessKey = accessKey.getSecretKey();
                }
                accessKeyMetadata.add(accessKeyResult);
            }
        }
        this.isTruncated = isTruncated;
        this.marker = marker;
    }
}
