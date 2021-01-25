package cn.ctyun.oos.iam.server.entity;

/**
 * 解析ARN错误
 * @author wangduo
 *
 */
public class ParseArnException extends Exception {

    private static final long serialVersionUID = 1L;

    public ParseArnException() {
        super();
    }

    public ParseArnException(String message) {
        super(message);
    }

    public ParseArnException(String message, Throwable cause) {
        super(message, cause);
    }

    public ParseArnException(Throwable cause) {
        super(cause);
    }
}
