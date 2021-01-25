package cn.ctyun.oos.iam.server.util;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

import com.google.zxing.WriterException;

/**
 * MFA TOTP 实现
 * 
 * @see http://thegreyblog.blogspot.com/2011/12/google-authenticator-using-it-in-your.html
 * @see http://code.google.com/p/google-authenticator
 * @see http://tools.ietf.org/id/draft-mraihi-totp-timebased-06.txt
 * 
 * @author wangduo
 */
public class MFAAuthenticator {
    
    /**
     * 最多可偏移的时间窗口，每一个时间窗口为30s
     * 解决客户端与服务器端时间差的问题
     */
    public static final int WINDOW_SIZE = 5;
    
    private static final int SECRET_SIZE = 40;
    
    /**
     * Base32StringSeed 生成
     * @return Base32StringSeed
     */
    public static String generateBase32StringSeed() {
        SecureRandom sr = new SecureRandom();
        byte[] buffer = sr.generateSeed(SECRET_SIZE);
        Base32 codec = new Base32();
        byte[] bEncodedKey = codec.encode(buffer);
        String encodedKey = new String(bEncodedKey);
        return encodedKey;
    }
    
    public static void main(String[] args) {
        System.out.println(generateBase32StringSeed());
    }
    
    /**
     * 生成二维码字节数组
     * @param virtualMFADeviceName
     * @param accountId
     * @param secret
     * @return
     * @throws WriterException
     * @throws IOException
     */
    public static String generateQRCodePNG(String virtualMFADeviceName, String accountId, String secret) throws WriterException, IOException {
        String issuer = "OOS Services";
        String format = "otpauth://totp/%s:%s@%s?secret=%s&issuer=%s";
        String qrCodeString = String.format(format, issuer, virtualMFADeviceName, accountId, secret, issuer);
        return QRCodeUtil.generateBase64(qrCodeString.replace(" ", "%20"));
    }
    
    /**
     * 校验用户输入的验证码
     * @param secret 用户的秘钥
     * @param code 用户输入的验证码
     * @return
     */
    public static boolean checkCode(String secret, long code) {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);
        // 时间窗口大小为30s，计算出时间窗口
        long t = System.currentTimeMillis() / 1000L / 30L;
        // 校验前后WINDOW_SIZE数量的时间窗口的code
        for (int i = -WINDOW_SIZE; i <= WINDOW_SIZE; ++i) {
            long hash = verifyCode(decodedKey, t + i);
            if (hash == code) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 验证MFA两个连续的验证码是否正确
     * @param secret 密钥
     * @param code1 第一个验证码
     * @param code2 第二个验证码
     * @return
     */
    public static boolean checkCode(String secret, long code1, long code2) {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);
        long t = System.currentTimeMillis() / 1000L / 30L;
        for (int i = -WINDOW_SIZE; i <= WINDOW_SIZE; ++i) {
            long hash1 = verifyCode(decodedKey, t + i);
            long hash2 = verifyCode(decodedKey, t + i + 1);
            if (hash1 == code1 && hash2 == code2) {
                return true;
            }
        }
        return false;
    }
    
    
    private static int verifyCode(byte[] key, long t)  {
        byte[] data = new byte[8];
        long value = t;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }
        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            mac.init(signKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        byte[] hash = mac.doFinal(data);
        int offset = hash[20 - 1] & 0xF;
        // We're using a long because Java hasn't got unsigned int.
        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            // We are dealing with signed bytes:
            // we just keep the first byte.
            truncatedHash |= (hash[offset + i] & 0xFF);
        }
        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;
        return (int) truncatedHash;
    }
}