package com.meituan.logan.web.parser;

import com.meituan.logan.web.enums.ResultEnum;
import com.meituan.logan.web.model.Tuple;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.core.io.support.PropertiesLoaderUtils;

import javax.annotation.PreDestroy;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.GZIPInputStream;

/**
 * @author foree
 * @since logan-web 1.0
 */
public class LoganProtocol {

    private static final Logger LOGGER = Logger.getLogger(LoganProtocol.class);

    private static final char ENCRYPT_CONTENT_START = '\1';

    private static final String AES_ALGORITHM_TYPE = "AES/CBC/NoPadding";

    private static AtomicBoolean initialized = new AtomicBoolean(false);

    private static boolean VERBOSE;
    private static boolean GREEDY;

    static {
        initialize();
    }

    private ByteBuffer wrap;
    private FileOutputStream fileOutputStream;

    public LoganProtocol(InputStream stream, File file) {
        try {
            int ch = 0;
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            while ((ch = stream.read()) != -1) {
                outputStream.write(ch);
            }

            wrap = ByteBuffer.wrap(outputStream.toByteArray());

            outputStream.close();

            fileOutputStream = new FileOutputStream(file);
        } catch (IOException e) {
            System.out.println("init error: " + e.getMessage());
        }
    }

    int i = 0;

    public ResultEnum process() {
        while (wrap.hasRemaining()) {
            byte header = wrap.get();
            while (header == ENCRYPT_CONTENT_START) {
                i++;
                System.out.println("get block: " + i);

                int length = wrap.getInt();
                if (GREEDY) {
                    if (length <= 0) {
                        continue;
                    }
                }

                byte[] encrypt = new byte[length];
                if (!tryGetEncryptContent(encrypt) || !decryptAndAppendFile(encrypt)) {
                    if (!GREEDY) { // non-greedy
                        return ResultEnum.ERROR_DECRYPT;
                    }
                    // continue
                }

                try {
                    header = wrap.get();
                } catch (java.nio.BufferUnderflowException e) {
                    System.out.println("tryGetEncryptContent error: " + e.getMessage());
                    return ResultEnum.ERROR_DECRYPT;
                }

            }
        }
        System.out.println("decrypt content done!");
        return ResultEnum.SUCCESS;
    }

    private boolean tryGetEncryptContent(byte[] encrypt) {
        try {
            wrap.get(encrypt);
        } catch (java.nio.BufferUnderflowException e) {
            System.out.println("tryGetEncryptContent error: " + e.getMessage());
            if (GREEDY) {// greedy mode, match string more
                wrap.position(wrap.position() - 3); // 如果读出的字节数量太大，重置回 ENCRYPT_CONTENT_START 的后一个字节，尝试修复读取后边的代码块
            }

            return false;
        }
        return true;
    }

    private boolean decryptAndAppendFile(byte[] encrypt) {
        System.out.println("decryptAndAppendFile......: position: " + (wrap.position() - encrypt.length) + ", length: " + encrypt.length);
        boolean result = false;
        try {
            Cipher aesEncryptCipher = Cipher.getInstance(AES_ALGORITHM_TYPE);
            Tuple<String, String> secureParam = getSecureParam();
            if (secureParam == null) {
                return false;
            }
            SecretKeySpec secretKeySpec = new SecretKeySpec(secureParam.getFirst().getBytes(), "AES");
            aesEncryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(secureParam.getSecond().getBytes()));
            byte[] compressed = aesEncryptCipher.doFinal(encrypt);
            byte[] plainText = decompress(compressed);
            if (VERBOSE) {
                System.out.println("deLogan: " + new String(plainText));
            }
            result = true;

            String output = new String(plainText);
            // do format
//            if(null != plainText && plainText.length > 0) {
//                String[] outputList = output.split("\\n");
//                for (String s : outputList) {
//                    // find "l"
//                    int start = s.indexOf("\"l\":") + 4;
//                    int end = s.substring(start).indexOf(",") + start;
//                    String timeString = s.substring(start, end);
//                    long time = Long.valueOf(timeString);
//                    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");
//                    String formatedTime = "\"" + dateFormat.format(new Date(time)) + "\"";
//                    output = output.replace(timeString, formatedTime);
//                }
//            }

            fileOutputStream.write(output.getBytes());
            fileOutputStream.flush();
        } catch (Exception e) {
            System.out.println("decryptAndAppendFile error: " + e.getMessage());
        }
        return result;
    }

    private static byte[] decompress(byte[] contentBytes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            InputStream inputStream = new GZIPInputStream(new ByteArrayInputStream(contentBytes));

            int ch = 0;
            while ((ch = inputStream.read()) != -1) {
                out.write(ch);
            }
            if (VERBOSE) {
                System.out.println("decompress: " + new String(out.toByteArray()));
            }
            return out.toByteArray();
        } catch (IOException e) {
            System.out.println("decompress error: " + e.getMessage());
            /*ByteArrayOutputStream errorOut = new ByteArrayOutputStream();
            try {
                errorOut.write(e.getMessage().getBytes());
                errorOut.write('\n');
                errorOut.write(out.toByteArray());
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
            return errorOut.toByteArray();*/
            return "".getBytes();
        }
    }

    @PreDestroy
    public void closeFileSteam() {
        try {
            fileOutputStream.close();
        } catch (IOException e) {
            LOGGER.error(e);
        }
    }

    /**
     * BouncyCastle作为安全提供，防止我们加密解密时候因为jdk内置的不支持改模式运行报错。
     **/
    private static void initialize() {
        if (initialized.get()) {
            return;
        }
        Security.addProvider(new BouncyCastleProvider());
        initialized.set(true);
    }


    private static Tuple<String, String> getSecureParam() {
        try {
            Properties properties = PropertiesLoaderUtils.loadAllProperties("secure.properties");
            Tuple<String, String> tuple = new Tuple<>();
            tuple.setFirst(properties.getProperty("AES_KEY"));
            tuple.setSecond(properties.getProperty("IV"));
            return tuple;
        } catch (IOException e) {
            LOGGER.error(e);
        }
        return null;
    }
}