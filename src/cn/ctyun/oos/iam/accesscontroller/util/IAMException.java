package cn.ctyun.oos.iam.accesscontroller.util;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.common.BaseException;

/**
 * IAM异常
 * @author wangduo
 *
 */
public class IAMException extends BaseException {

    private static final long serialVersionUID = 1L;
    
    /** 错误列表，其中携带messageCode，用于前端获取中文异常信息 */
    public List<IAMErrorMessage> errorMessages;
    
    /**
     * 单条错误信息异常
     * @param status
     * @param code
     * @param errorMessage
     */
    public IAMException(int status, String code, IAMErrorMessage errorMessage) {
        this.status = status;
        this.code = code;
        this.message = errorMessage.generateMessage();
        this.errorMessages = new ArrayList<>(1);
        errorMessages.add(errorMessage);
    }
    
    /**
     * 多条错误信息异常
     * @param status
     * @param code
     * @param message
     * @param errorMessages
     */
    public IAMException(int status, String code, String message, List<IAMErrorMessage> errorMessages) {
        this.status = status;
        this.code = code;
        this.message = message;
        this.errorMessages = errorMessages;
    }

}
