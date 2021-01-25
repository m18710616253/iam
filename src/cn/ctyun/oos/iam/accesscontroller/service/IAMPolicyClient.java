package cn.ctyun.oos.iam.accesscontroller.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.amazonaws.services.s3.Headers;
import com.amazonaws.services.s3.internal.ServiceUtils;

import cn.ctyun.common.BaseException;
import cn.ctyun.common.Consts;
import cn.ctyun.common.conf.GlobalIamConfig;
import cn.ctyun.common.conf.OOSConfig;
import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;
import cn.ctyun.oos.iam.accesscontroller.policy.PolicyParseException;
import cn.ctyun.oos.iam.signer.ErrorMessage;
import cn.ctyun.oos.iam.signer.Utils;
import common.util.JsonUtils;

/**
 * 客户端策略获取接口， 封装了向IAM 发送http请求代码。
 * 
 * @author wangxs
 *
 */
public class IAMPolicyClient {
    
    private static final Log log = LogFactory.getLog(IAMPolicyClient.class);
    
    private static final String HTTP_METHOD_POST = "POST";
    
    /**
     * 获取单用户策略。
     */
    public static List<AccessPolicy> getUserPolicies(String accountId, String userName)throws IOException, BaseException{
        // JSON请求参数
        JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put("accountId", accountId);
            jsonObject.put("userName", userName);
        } catch (JSONException e) {
            // 该错误不会发生，不做处理
            log.error(e.getMessage(), e);
        }
        InputStream is = null;
        try {
            is = getPoliciesStreamViaHttp(GlobalIamConfig.getResource()+"/policy", jsonObject.toString());
            return parsePolicy(is);
        } finally {
            try {
                if (null != is)
                    is.close();
            } catch (Exception e){
                log.error(e.getMessage(), e);
            }
        }
    }
    
    /**
           * 获取多用户策略。
           * 如果是白名单内的缓存加载，不需要提供username，将账户下的所有用户策略全部返回。 
     * @param userKeys [accountId|username]
     * */
    public static Map<String, List<AccessPolicy>> getUsersPolicies(Collection<String> userKeys) 
            throws BaseException, IOException{
        String body = JsonUtils.toJsonFromCollection(userKeys);
        InputStream is = null;
        try {
            is = getPoliciesStreamViaHttp(GlobalIamConfig.getResource()+"/policies", body);
            return parseUsersPolicies(is);
        } finally {
            try{
                if(null != is)
                    is.close();
            } catch (Exception e){
                log.error(e.getMessage(), e);
            }
        }
    }
    
    private static Map<String, List<AccessPolicy>> parseUsersPolicies(InputStream inputStream) throws IOException,BaseException{
        Map<String, List<AccessPolicy>> map = new HashMap<String, List<AccessPolicy>>();
        try {
            String json = IOUtils.toString(inputStream, Consts.STR_UTF8);
            JSONObject jsonObj = new JSONObject(json);
            @SuppressWarnings("unchecked")
            Iterator<String> iterator = jsonObj.keys();
            String policyDocument = "";
            while(iterator.hasNext()) {
                String key = iterator.next();
                //如果一条策略解析失败，继续解析下一条
                try {
                    JSONArray arrays = jsonObj.getJSONArray(key);
                    List<AccessPolicy> policies = new ArrayList<>();
                    for (int i = 0; i < arrays.length(); i++) {
                        policyDocument = arrays.getString(i);
                        policies.add(AccessPolicy.fromJson(policyDocument));
                    }
                    map.put(key, policies);
                } catch (JSONException | PolicyParseException e) {
                    log.error("Parse policy json failed. user: " + key + ", policyDocument:" + policyDocument, e);
                }
            }
        } catch (JSONException e) {
            log.error(e.getMessage(), e);
        }
        return map;
    }
    
    private static List<AccessPolicy> parsePolicy(InputStream inputStream) throws IOException, BaseException{
        try {
            String str = IOUtils.toString(inputStream, Consts.STR_UTF8);
            JSONArray arrays = new JSONArray(str);
            List<AccessPolicy> policies = new ArrayList<>();
            for (int i = 0; i < arrays.length(); i++) {
                String policyDocument = arrays.getString(i);
                AccessPolicy policy = AccessPolicy.fromJson(policyDocument);
                policies.add(policy);
            }
            return policies;
        } catch (JSONException | PolicyParseException je) {
            log.error(je.getMessage(), je);
            throw new BaseException(ErrorMessage.ERROR_GET_POLICY, 500, ErrorMessage.ERROR_CODE_500);
        }
    }

    private static InputStream getPoliciesStreamViaHttp(String resource, String body) throws IOException {
        URL url = new URL(GlobalIamConfig.getProtocol(), GlobalIamConfig.getIamHost(), 
                GlobalIamConfig.getPort(), resource);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // 服务间的AK签名认证
        HashMap<String,String> map=new HashMap<>();
        String date=ServiceUtils.formatRfc822Date(new Date());
        map.put(Headers.CONTENT_TYPE,"application/json");
        map.put(Headers.DATE, date);
        String auth = Utils.authorize(HTTP_METHOD_POST, GlobalIamConfig.getAk(), GlobalIamConfig.getSk(),
                map);
        conn.setRequestProperty(Headers.DATE, date);
        conn.setRequestProperty(Headers.CONTENT_TYPE, "application/json");
        conn.setRequestProperty(Consts.AUTHORIZATION, auth);
        conn.setConnectTimeout(OOSConfig.getInternalConnTimeout());
        conn.setReadTimeout(OOSConfig.getInternalReadTimeout());
        conn.setRequestMethod(HTTP_METHOD_POST);
        conn.setDoInput(true);
        conn.setDoOutput(true);
        OutputStream out = conn.getOutputStream();
        out.write(body.getBytes());
        out.flush();
        int code = conn.getResponseCode();
        if (code == HttpURLConnection.HTTP_OK) {
            return conn.getInputStream();
        } else {
            String msg = getErrorMsg(conn);
            log.error("get iam user policy failed, request url: " + url + ", request body:" + body);
            throw new IOException(msg);
        }
    }

    /**
            获取错误信息
     * 
     * @param conn
     * @return
     */
    private static String getErrorMsg(HttpURLConnection conn) {
        try (InputStream in = conn.getInputStream()) {
            return IOUtils.toString(in, Consts.STR_UTF8);
        } catch (IOException e) {
            try (InputStream err = conn.getErrorStream()) {
                if (err != null) {
                    return IOUtils.toString(err, Consts.STR_UTF8);
                } else {
                    return null;
                }
            } catch (IOException e2) {
                log.error(e2.getMessage(), e2);
                return null;
            }
        }
    }
}
