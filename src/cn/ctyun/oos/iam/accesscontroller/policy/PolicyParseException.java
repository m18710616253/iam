package cn.ctyun.oos.iam.accesscontroller.policy;

/**
 * 策略解析异常
 * @author wangduo
 *
 */
public class PolicyParseException extends Exception {

    private static final long serialVersionUID = 5870430979674026965L;
    
    /** 错误信息码 */
    public String messageCode;
    /** 消息中的变量 */
    public Object[] params;
    
    public PolicyParseException() {
        super();
    }

    public PolicyParseException(String messageCode, String message, Object... params) {
        super(message);
        this.messageCode = messageCode;
        this.params = params;
    }
    
    public PolicyParseException(String messageCode, String message, Throwable cause) {
        super(message, cause);
        this.messageCode = messageCode;
    }
    
    public PolicyParseException(String message, Throwable cause) {
        super(message, cause);
    }

    public PolicyParseException(Throwable cause) {
        super(cause);
    }

}
