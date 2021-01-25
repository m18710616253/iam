package cn.ctyun.oos.iam.server.result;

import java.util.List;

/**
 * 分页结果
 * @author wangduo
 *
 * @param <T>
 */
public class PageResult<T> {

    /** 是否还有下一页 */
    public boolean isTruncated;
    
    /** 下一页的marker */
    public String marker;
    
    /** 当前页的数据 */
    public List<T> list;
    
    /** marker列表，从第二页开始 */
    public List<String> markers;
    
    /** 符合条件的数据总数 */
    public Long total;
}
