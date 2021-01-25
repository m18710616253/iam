package cn.ctyun.oos.iam.server.util;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import com.amazonaws.services.s3.Headers;

import cn.ctyun.common.Consts;

/**
 * HTTP工具
 * @author wangduo
 *
 */
public class HttpUtils {

    /**
     * 向响应中写入返回字符串
     * @param resp
     * @param body
     * @throws IOException
     */
    public static void writeResponseEntity(HttpServletResponse resp, String body) throws IOException {
        resp.setCharacterEncoding(Consts.STR_UTF8);
        if (body != null) {
            resp.setIntHeader(Headers.CONTENT_LENGTH, body.getBytes(Consts.CS_UTF8).length);
            resp.getWriter().write(body);
        } else
            resp.setIntHeader(Headers.CONTENT_LENGTH, 0);
    }

}
