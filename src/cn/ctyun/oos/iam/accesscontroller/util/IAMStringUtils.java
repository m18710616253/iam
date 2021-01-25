package cn.ctyun.oos.iam.accesscontroller.util;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.UUID;
import java.util.regex.Matcher;

import cn.ctyun.common.Consts;
import common.util.HexUtils;

/**
 * 字符串工具
 * @author wangduo
 *
 */
public class IAMStringUtils {

    /**
     * 首字母转大写
     * @param str
     * @return
     */
    public static String firstCharUpperCase(String str) {
        if (str == null || str.length() == 0) {
            return str;
        }
        return str.substring(0, 1).toUpperCase() + str.substring(1);
    }
    
    /**
     * 首字母转小写
     * @param str
     * @return
     */
    public static String firstCharLowerCase(String str) {
        if (str == null || str.length() == 0) {
            return str;
        }
        return str.substring(0, 1).toLowerCase() + str.substring(1);
    }
    
    /**
     * 生成一个UUID
     * @return
     */
    public static String generateId() {
        return UUID.randomUUID().toString().replaceAll("-", "");
    }
    
    /**
     * 将accountId转换为onwerId
     * @param accountId
     * @return
     */
    public static long getOwnerId(String accountId) {
        return Long.parseUnsignedLong(accountId, 36);
    }
    
    /**
     * 将onwerId转换为accountId
     * @param ownerId
     * @return
     */
    public static String getAccountId(long ownerId) {
        String accountId = Long.toUnsignedString(ownerId, 36);
        accountId = String.format("%13s", accountId).replaceAll(" ", "0");
        return accountId;
    }
    
    /**
     * 密码加密
     * @param password
     * @return
     */
    public static String passwordDecode(String password) {
        if (password == null)
            return null;
        byte[] buf = HexUtils.toByteArray(password);
        for (int i = 0; i < buf.length / 2; i++) {
            byte tmp = buf[i];
            buf[i] = buf[buf.length - 1 - i];
            buf[buf.length - 1 - i] = tmp;
        }
        return new String(buf, Consts.CS_UTF8);
    }
    
    /**
     * 密码解密
     * @param password
     * @return
     */
    public static String passwordEncode(String password) {
        if (password == null) {
            return null;
        }
        byte[] buf = password.getBytes(Consts.CS_UTF8);
        for (int i = 0; i < buf.length / 2; i++) {
            byte tmp = buf[i];
            buf[i] = buf[buf.length - 1 - i];
            buf[buf.length - 1 - i] = tmp;
        }
        return HexUtils.toHexString(buf);
    }
    
    /**
     * 包含小写字母
     * @param str
     * @return
     */
    public static boolean containsLowercaseCharacter(String str) {
        return containsCharacter(str, 'a', 'z');
    }
    
    /**
     * 包含大写字母
     * @param str
     * @return
     */
    public static boolean containsUppercaseCharacter(String str) {
        return containsCharacter(str, 'A', 'Z');
    }
    
    /**
     * 包含数字
     * @param str
     * @return
     */
    public static boolean containsNumber(String str) {
        return containsCharacter(str, '0', '9');
    }
    
    /**
     * 判断字符串是否包含指定范围内的字符
     * @param str
     * @param from
     * @param to
     * @return
     */
    private static boolean containsCharacter(String str, char from, char to) {
        for (char c : str.toCharArray()) {
            if (c >= from && c <= to) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 对字符串进行 URL encode
     * 对空格 encode 后得到的加号，特殊处理，转会为%20
     * @param str
     * @return
     */
    public static String urlEncode(String str) {
        try {
            // 进行URLEncode
            String encodeStr = URLEncoder.encode(str, "UTF-8");
            return encodeStr.replaceAll("\\+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    
    /**
     * 将字符串中的子用户名策略变量替换为指定的用户名
     * @param str
     * @param userName 子用户名
     * @return
     */
    public static String replaceUserNameVariable(String str, String userName) {
        String replacement = Matcher.quoteReplacement(userName);
        return str.replaceAll("\\$\\{ctyun:username\\}", replacement);
    }
}
