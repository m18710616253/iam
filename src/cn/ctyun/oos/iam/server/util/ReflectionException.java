package cn.ctyun.oos.iam.server.util;

/**
 * 反射异常
 * @author wangduo
 *
 */
public class ReflectionException extends RuntimeException {

    private static final long serialVersionUID = -5013823009905170820L;

    public ReflectionException() {
        super();
    }
    
    public ReflectionException(String message) {
        super(message);
    }

    public ReflectionException(String message, Throwable cause) {
        super(message, cause);
    }

    public ReflectionException(Throwable cause) {
        super(cause);
    }
}
