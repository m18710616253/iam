package cn.ctyun.oos.iam.accesscontroller.util;

/**
 * IAM错误信息
 * @author wangduo
 *
 */
public class IAMErrorMessage {

    /** 消息code */
    public String messageCode;
    /** 消息内容 */
    public String message;
    /** 消息中的变量 */
    public Object[] params;
    
    public IAMErrorMessage(String messageCode, String message, Object... params) {
        this.messageCode = messageCode;
        this.message = message;
        this.params = params;
    }
    
    /**
     * 生成完整错误信息
     * @return
     */
    public String generateMessage() {
        if (params == null || params.length == 0) {
            return message;
        }
        return String.format(message, params);
    }

    @Override
    public String toString() {
        return generateMessage();
    }
    
    
}
