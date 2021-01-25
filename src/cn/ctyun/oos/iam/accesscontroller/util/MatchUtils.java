package cn.ctyun.oos.iam.accesscontroller.util;

/**
 * 匹配工具
 * @author wangduo
 *
 */
public class MatchUtils {

    /**
     * 对字符串和字符串规则进行匹配
     * 规则支持'?','*'的匹配
     * '?'代表单个字符，'*'代表多个字符
     * @param str 待匹配字符串
     * @param pattern 规则字符串
     * @return
     */
    public static boolean isMatch(String str, String pattern) {
    
        // 字符串上一个星号匹配到的位置
        int matchIndex = 0;
        // 字符串规则上一个星号的位置
        int starIndex = -1;
        // 字符串匹配到的位置
        int sIndex = 0;
        // 字符串规则匹配到的位置
        int pIndex = 0;
    
        while (sIndex < str.length()) {
            if (pIndex < pattern.length() && (pattern.charAt(pIndex) == '?' || str.charAt(sIndex) == pattern.charAt(pIndex))) {// 相同
                pIndex++;
                sIndex++;
            } else if (pIndex < pattern.length() && pattern.charAt(pIndex) == '*') {
                starIndex = pIndex;
                pIndex = starIndex + 1;
                matchIndex = sIndex;
            } else if (starIndex != -1) {
                pIndex = starIndex + 1;
                matchIndex++;
                sIndex = matchIndex;
            } else {
                return false;
            }
        }
        while (pIndex < pattern.length() && pattern.charAt(pIndex) == '*') {
            pIndex++;
        }
        return pIndex == pattern.length();
    }

}
