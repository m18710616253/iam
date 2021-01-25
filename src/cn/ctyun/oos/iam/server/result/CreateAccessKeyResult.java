package cn.ctyun.oos.iam.server.result;

import com.fasterxml.jackson.core.JsonProcessingException;

import cn.ctyun.oos.iam.server.util.JSONUtils;

/**
 * 创建AccessKey结果
 * @author wangduo
 *
 */
public class CreateAccessKeyResult extends Result {

    public AccessKeyResult accessKey = new AccessKeyResult();
    
    @Override
    public String toJson() throws JsonProcessingException {
        CreateAccessKeyResult trailResult = new CreateAccessKeyResult();
        trailResult.accessKey.accessKeyId = accessKey.accessKeyId;
        trailResult.accessKey.status = accessKey.status;
        trailResult.accessKey.userName = accessKey.userName;
        trailResult.accessKey.createDate = accessKey.createDate;
        return JSONUtils.toTrailJSON(trailResult);
    }
}
