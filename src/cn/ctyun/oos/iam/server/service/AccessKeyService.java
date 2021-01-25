package cn.ctyun.oos.iam.server.service;

import java.io.IOException;
import java.security.SecureRandom;

import cn.ctyun.common.Consts;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.metadata.AkSkMeta;
import common.util.HexUtils;

/**
 * AccessKey通用功能
 * @author wangduo
 *
 */
public class AccessKeyService {

    private static MetaClient client = MetaClient.getGlobalClient();
    
    private static SecureRandom random = new SecureRandom();
    
    /**
     * 创建一个accessKey
     * @param accessKey
     * @return
     * @throws IOException 
     */
    public static AkSkMeta create(AkSkMeta accessKey) throws IOException {
        accessKey.accessKey = randomAccessKeyId();
        accessKey.setSecretKey(randomSecretAccessKey());
        accessKey.createDate = System.currentTimeMillis();
        // 保存AK，如果accessKeyId重复，重新生成并保存
        while (!client.akskInsert(accessKey)) {
            accessKey.accessKey = randomAccessKeyId();
        }
        return accessKey;
    }

    /**
     * 删除accessKey
     * @param accessKey
     * @throws IOException
     */
    public static void delete(AkSkMeta accessKey) throws IOException {
        client.akskDelete(accessKey);
    }
    
    private static String randomAccessKeyId() {
        return randomKey(Consts.ACCESS_KEY_LENGTH / 2);
    }
    
    private static String randomSecretAccessKey() {
        return randomKey(Consts.SECRET_KEY_LENGTH / 2);
    }
    
    private static String randomKey(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return HexUtils.toHexString(bytes);
    }
}
