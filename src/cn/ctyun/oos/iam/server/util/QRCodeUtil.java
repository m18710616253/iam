package cn.ctyun.oos.iam.server.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

/**
 * 二维码生成工具类
 */
public final class QRCodeUtil {

    private static final String IMAGE_FORMAT = "PNG";
    
	/**
	 * 生成二维码
	 * @throws WriterException 
	 * @throws IOException 
	 */
	public static void generate(OutputStream outputStream, String content, int width, int height, String format) throws WriterException, IOException {
		Map<EncodeHintType, Object> hints = new HashMap<>();
		hints.put(EncodeHintType.CHARACTER_SET, "utf-8");
		// 设置纠错率，分为L、M、H三个等级，等级越高，纠错率越高，但存储的信息越少
		hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
		// 设置边距，默认是5
		hints.put(EncodeHintType.MARGIN, 2);
		BitMatrix matrix = new MultiFormatWriter().encode(content, BarcodeFormat.QR_CODE, width, height, hints);
		MatrixToImageWriter.writeToStream(matrix, format, outputStream);
	}

	public static void generate(OutputStream outputStream, String content) throws WriterException, IOException {
		generate(outputStream, content, 200, 200, IMAGE_FORMAT);
	}

    /**
     * 生成Base64g格式的的二维码
     * 
     * @throws IOException
     * @throws WriterException
     */
    public static String generateBase64(String content) throws WriterException, IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        generate(outputStream, content);
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(outputStream.toByteArray());
    }
	
	public static void main(String[] args) throws IOException, WriterException {
		generate(new FileOutputStream(new File("d:\\qrcode.jpg")), "WE1231238239128sASDASDSADSDWEWWREWRERWSDFDFSDSDF123123123123213123", 200, 200, IMAGE_FORMAT);
	}

}