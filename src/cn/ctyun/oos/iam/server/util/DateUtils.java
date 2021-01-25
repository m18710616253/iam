package cn.ctyun.oos.iam.server.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import org.apache.commons.lang.time.DateFormatUtils;

/**
 * 时间格式化工具
 * @author wangduo
 *
 */
public class DateUtils {
    
    private static TimeZone UTC = TimeZone.getTimeZone("UTC");
    
    public static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    public static final String STS_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    public static final String YYYY_MM_DD_FORMAT = "yyyy-MM-dd";
    
    private static final SimpleDateFormat YYYY_MM_DD = new SimpleDateFormat(YYYY_MM_DD_FORMAT, Locale.ENGLISH);
    
    /**
     * 默认时间格式化方法
     * @param time
     * @return
     */
    public static String format(long time) {
        return DateFormatUtils.format(time, DEFAULT_DATE_FORMAT, UTC);
    }
    
    /**
     * STS授权时间格式
     * @param time
     * @return
     */
    public static String formatSts(long time) {
        return DateFormatUtils.format(time, STS_FORMAT, UTC);
    }
    
    
    public synchronized static Date parseYYYYMMDD(String date) throws ParseException {
        YYYY_MM_DD.setTimeZone(UTC);
        return YYYY_MM_DD.parse(date);
    }
    
    
}
