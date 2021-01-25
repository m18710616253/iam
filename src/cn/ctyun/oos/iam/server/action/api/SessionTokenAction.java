package cn.ctyun.oos.iam.server.action.api;

import java.security.SecureRandom;

import cn.ctyun.common.BaseException;
import cn.ctyun.common.Consts;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.server.action.Action;
import cn.ctyun.oos.iam.server.param.GetSessionTokenParam;
import cn.ctyun.oos.iam.server.result.GetSessionTokenResult;
import cn.ctyun.oos.iam.server.util.DateUtils;
import cn.ctyun.oos.metadata.TokenMeta;
import common.util.HexUtils;

/**
 * STS授权 Action
 * @author wangduo
 *
 */
@Action
public class SessionTokenAction {

    private static SecureRandom random = new SecureRandom();
    
    /**
     * 获取STS授权 
     * @param param
     * @return
     * @throws Exception 
     */
    public static GetSessionTokenResult getSessionToken(GetSessionTokenParam param) throws Exception {
        // STS授权访问，获取Token
        // 获取授权时间
        if (param.durationSeconds == null)
            throw new BaseException(400, "InvalidDurationSeconds");
        if (param.durationSeconds > 36 * 3600 || param.durationSeconds < 15 * 60)
            throw new BaseException(400, "InvalidDurationSeconds");
        // 生成token
        byte[] tokenBytes = new byte[64];
        random.nextBytes(tokenBytes);
        String tokenString = HexUtils.toHexString(tokenBytes);
        // 生成临时ak、sk
        byte bytes[] = new byte[Consts.ACCESS_KEY_LENGTH / 2];
        random.nextBytes(bytes);
        String stsAccessKey = "sts." + HexUtils.toHexString(bytes);
        bytes = new byte[Consts.SECRET_KEY_LENGTH / 2];
        random.nextBytes(bytes);
        String stsSecretKey = HexUtils.toHexString(bytes);
        // 构建TokenMeta
        TokenMeta tokenMeta = new TokenMeta(tokenString);
        tokenMeta.stsAccessKey = stsAccessKey;
        tokenMeta.setSecretKey(stsSecretKey);
        
        // 过期时间
        long t = System.currentTimeMillis() + param.durationSeconds * 1000;
        tokenMeta.expiration = DateUtils.formatSts(t);
        
        tokenMeta.ownerId =param.currentOwner.getId();
        MetaClient client = MetaClient.getGlobalClient();
        client.stsTokenInsert(tokenMeta);
        
        GetSessionTokenResult getSessionTokenResult = new GetSessionTokenResult();
        getSessionTokenResult.credentials.sessionToken = tokenString;
        getSessionTokenResult.credentials.accessKeyId = stsAccessKey;
        getSessionTokenResult.credentials.secretAccessKey = stsSecretKey;
        getSessionTokenResult.credentials.expiration = tokenMeta.expiration;
        return getSessionTokenResult;
    }
}
