package cn.ctyun.oos.iam.server.result;

import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * 接口返回结果基类
 * @author wangduo
 *
 */
public abstract class Result {

    /**
     * 将返回接口转换为json
     * @return
     * @throws JsonProcessingException 
     */
    public String toJson() throws JsonProcessingException {
        return null;
    }
}
