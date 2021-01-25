package cn.ctyun.oos.iam.server.action;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * 参数错误校验信息
 * @author wangduo
 *
 */
public class ValidationError {

    public List<String> messages = new ArrayList<String>();
    
    /**
     * 添加单条错误信息
     * @param message
     */
    public void addMessage(String message) {
        messages.add(message);
    }
    
    /**
     * 添加多条错误信息
     * @param message
     */
    public void addMessages(Collection<String> messages) {
        messages.addAll(messages);
    }
    
    
}
