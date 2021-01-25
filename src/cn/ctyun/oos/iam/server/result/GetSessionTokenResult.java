package cn.ctyun.oos.iam.server.result;

import com.fasterxml.jackson.core.JsonProcessingException;
import cn.ctyun.oos.iam.server.util.JSONUtils;

/**
 * STS授权返回结果
 * @author wangduo
 *
 */
public class GetSessionTokenResult extends Result {

    public Credentials credentials = new Credentials();
    
    public class Credentials {
        public String sessionToken;
        public String accessKeyId;
        public String secretAccessKey;
        public String expiration;
    }
    
    @Override
    public String toJson() throws JsonProcessingException {
        GetSessionTokenResult trailResult = new GetSessionTokenResult();
        trailResult.credentials.accessKeyId = credentials.accessKeyId;
        trailResult.credentials.expiration = credentials.expiration;
        return JSONUtils.toTrailJSON(trailResult);
    }
}
