package com.fan.myapplication;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import static org.apache.http.conn.ssl.SSLSocketFactory.STRICT_HOSTNAME_VERIFIER;

public class MainActivity extends AppCompatActivity {

    String httpsPath = "https://192.168.110.110:8443/hello";
    String httpPath = "http://192.168.110.110:8443/hello";

    String SERVER_CER_NAME = "server.cer";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        findViewById(R.id.okhttp_http_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            getHttpDataByOkhttp();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }).start();
            }
        });

        findViewById(R.id.urlconnection_http_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            getHttpDataByUrlConnection();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }).start();
            }
        });
        findViewById(R.id.urlconnection_https_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            getHttpsDataByUrlConnection();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }).start();

            }
        });
        findViewById(R.id.get_safe_from_server_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            getSafeFromServer();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }).start();
            }
        });
        findViewById(R.id.get_safe_from_server_button_sample).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            getSafeFromServerSample();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }).start();
            }
        });
        findViewById(R.id.check_self).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    X509Certificate certificate = getX509Certificate(MainActivity.this, SERVER_CER_NAME);
                    X509Certificate ca = getX509Certificate(MainActivity.this, "ca.cer");

                    // 这样就对啦, 是要用 证书 验证 根证书的 publicKey
                    certificate.verify(ca.getPublicKey());

                    // 或者根证书自己验证自己
                    ca.verify(ca.getPublicKey());

                    // 参考:https://stackoverflow.com/questions/18585222/java-x509certificate-issuer-validation
                    // 参考:https://stackoverflow.com/questions/12156734/public-key-verification-always-returns-signature-does-not-match
                    // 类似于:
                    ////        X509Certificate adminCert=genX509Cert(adminCertByte);//获取管理员证书
                    ////
                    ////        X509Certificate issuerCert=genX509Cert(issuerCertByte);//获取颁发者证书, 这个颁发者就是是CA 机构
                    ////
                    ////        PublicKey issuerPublicKey = issuerCert.getPublicKey();//获取颁发者公钥
                    ////
                    ////        adminCert.verify(issuerPublicKey);//验签

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    /**
     * 使用 OkHttp 获取Http数据
     * @throws Exception
     */
    public void getHttpDataByOkhttp() throws Exception {
        //创建OkHttpClient对象
        OkHttpClient client = new OkHttpClient();
        //创建Request
        Request request = new Request.Builder()
                .url(httpPath)//访问连接
                .get()
                .build();
        //创建Call对象
        Call call = client.newCall(request);
        //通过execute()方法获得请求响应的Response对象
        Response response = call.execute();
        if (response.isSuccessful()) {
            //处理网络请求的响应，处理UI需要在UI线程中处理
            byte[] bytes = response.body().bytes();
            String result = new String(bytes);
            Log.d("MMMMM", "okhttp:" + result);
        } else {
            Log.d("MMMMM", "okhttp: error");
        }
    }


    /**
     * 使用 HTTPUrlConnection 获取 http 数据
     * @throws Exception
     */
    public void getHttpDataByUrlConnection() throws Exception {

        URL url = new URL(httpPath);

        URLConnection urlConnection = url.openConnection();
        // 此处的urlConnection对象实际上是根据URL的 请求协议(此处是http)生成的URLConnection类的子类HttpURLConnection
        // 故此处最好将其转化 为HttpURLConnection类型的对象,以便用到 HttpURLConnection更多的API.如下:

        HttpURLConnection httpUrlConnection = (HttpURLConnection) urlConnection;

        // 设置是否向httpUrlConnection输出，因为这个是post请求，参数要放在
        // http正文内，因此需要设为true, 默认情况下是false;
        httpUrlConnection.setDoOutput(false); // 这里写true就是POST请求了

        // 设置是否从httpUrlConnection读入，默认情况下是true;
        httpUrlConnection.setDoInput(true);

        // 使用setRequestProperty可以设置一些属性， 比如头信息， 比如请求的方法


        // 设定请求的方法为"POST"，默认是GET
        httpUrlConnection.setRequestMethod("GET");

        // 连接，从上述第2条中url.openConnection()至此的配置必须要在connect之前完成，
        // connect 是真正建立连接， 不过也只是建立连接， 不发送数据
//        httpUrlConnection.connect();

        // 此处getOutputStream会隐含的进行connect
        // 所以在开发中不调用上述的connect()也可以)
        // 因为要向服务器发送数据， 肯定要在建立连接的基础上， 因此在getOutputStream方法内部会调用connect建立连接
//        OutputStream outStrm = httpUrlConnection.getOutputStream();


        // 调用HttpURLConnection连接对象的getInputStream()函数,
        // 将内存缓冲区中封装好的完整的HTTP请求报文发送到服务端。
//        InputStream inStrm = httpUrlConnection.getInputStream(); // <===注意，实际发送请求的代码段就在这里
        //  getInputStream方法内部也会调用connect， 因为有时候不需要向ouputStream中写入数据， 直接通过URL就可以带参数， 这时直接调用getInputStream就可以保证先建立连接， 然后发送请求， 并且获取返回数据

        InputStream inputStream;
        int status = httpUrlConnection.getResponseCode();

        if (status != HttpURLConnection.HTTP_OK) {
            inputStream = httpUrlConnection.getErrorStream();
        } else {
            inputStream = httpUrlConnection.getInputStream();
        }
        byte[] bytes = new byte[1024];
        int read = inputStream.read(bytes);
        String result = new String(bytes, 0, read);

        Log.d("MMMMM", "conn" + result);
        //Toast.makeText(MainActivity.this, result, Toast.LENGTH_LONG).show();

        inputStream.close();
    }

    /**
     * 使用 HttpsUrlConnection 获取 Https 数据
     * @throws Exception
     */
    public void getHttpsDataByUrlConnection() throws Exception {


        TrustManager[] trustManagers = new TrustManager[]{new SSLTrustAllManager()};


        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagers, null);

        URL url = new URL(httpsPath);
        HttpsURLConnection httpsURLConnection = (HttpsURLConnection) url.openConnection();
        httpsURLConnection.setSSLSocketFactory(sslContext.getSocketFactory());

        httpsURLConnection.setHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String s, SSLSession sslSession) {
                return true;
            }
        });

        InputStream inputStream;
        int status = httpsURLConnection.getResponseCode();

        if (status != HttpURLConnection.HTTP_OK) {
            inputStream = httpsURLConnection.getErrorStream();
        } else {
            inputStream = httpsURLConnection.getInputStream();
        }
        byte[] bytes = new byte[1024];
        int read = inputStream.read(bytes);
        String result = new String(bytes, 0, read);

        Log.d("MMMMM", "https conn: " + result);
        //Toast.makeText(MainActivity.this, result, Toast.LENGTH_LONG).show();

        inputStream.close();

    }


    /**
     * 用预埋证书来生成 TrustManger, 然后获取 Https 数据
     * @throws Exception
     */
    public void getSafeFromServer() throws Exception {


        URL url = new URL(httpsPath);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

        //创建X.509格式的CertificateFactory
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        //从asserts中获取证书的流
        InputStream cerInputStream = getAssets().open(SERVER_CER_NAME);
        //ca是java.security.cert.Certificate，不是java.security.Certificate，
        //也不是javax.security.cert.Certificate
        Certificate cert;
        try {
            //证书工厂根据证书文件的流生成证书Certificate
            cert = cf.generateCertificate(cerInputStream);
            System.out.println("证书生成完成 ca=" + ((X509Certificate) cert).getSubjectDN());
        } finally {
            cerInputStream.close();
        }

        // 创建一个默认类型的KeyStore，存储我们信任的证书
        String keyStoreType = KeyStore.getDefaultType();
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        //将证书作为信任的证书放入到keyStore中
        keyStore.setCertificateEntry("myserver", cert);

        //TrustManagerFactory是用于生成TrustManager的，我们创建一个默认类型的TrustManagerFactory
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        //用我们之前的keyStore实例初始化TrustManagerFactory，这样tmf就会信任keyStore中的证书
        tmf.init(keyStore);
        //通过tmf获取TrustManager数组，TrustManager也会信任keyStore中的证书
        TrustManager[] trustManagers = tmf.getTrustManagers();

        //创建TLS类型的SSLContext对象， that uses our TrustManager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        //用上面得到的trustManagers初始化SSLContext，这样sslContext就会信任keyStore中的证书
        sslContext.init(null, trustManagers, null);

        //通过sslContext获取SSLSocketFactory对象
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        //将sslSocketFactory通过setSSLSocketFactory方法作用于HttpsURLConnection对象
        //这样conn对象就会信任我们之前得到的证书对象
        conn.setSSLSocketFactory(sslSocketFactory);


        // 这里不要自己写, 用自带的就好了
        conn.setHostnameVerifier(STRICT_HOSTNAME_VERIFIER);
//        conn.setHostnameVerifier(new HostnameVerifier() {
//            @Override
//            public boolean verify(String hostname, SSLSession sslSession) {
//                if ("192.168.110.42".equals(hostname)) {
//                    return true;
//                } else {
//                    HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
//                    return hv.verify(hostname, sslSession);
//                }
//            }
//        });

        InputStream inputStream;
        int status = conn.getResponseCode();

        if (status != HttpURLConnection.HTTP_OK) {
            inputStream = conn.getErrorStream();
        } else {
            inputStream = conn.getInputStream();
        }
        byte[] bytes = new byte[1024];
        int read = inputStream.read(bytes);
        String result = new String(bytes, 0, read);

        Log.d("MMMMM", "getSafeFromServer: " + result);

        inputStream.close();

    }

    /**
     * 使用自行验签的方式获取 Https 数据
     *
     * 自行验证包括两种:
     * 1. 锁定公钥, 参考PubKeyManager
     * 2. 自行验证签名 参考: MyX509TrustManager
     *
     * @throws Exception
     */
    public void getSafeFromServerSample() throws Exception {


        //创建X.509格式的CertificateFactory
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        //从asserts中获取证书的流
        InputStream cerInputStream = getAssets().open(SERVER_CER_NAME);
        //ca是java.security.cert.Certificate，不是java.security.Certificate，
        //也不是javax.security.cert.Certificate
        Certificate cert;
        try {
            //证书工厂根据证书文件的流生成证书Certificate
            cert = cf.generateCertificate(cerInputStream);
            System.out.println("证书生成完成 ca=" + ((X509Certificate) cert).getSubjectDN());
        } finally {
            cerInputStream.close();
        }

        URL url = new URL(httpsPath);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

        SSLContext sslContext = SSLContext.getInstance("TLS");

        MyX509TrustManager myX509TrustManager = new MyX509TrustManager(getX509Certificate(this, SERVER_CER_NAME), getX509Certificate(this, "ca.cer"));
//        TrustManager manager = new PubKeyManager();

        TrustManager[] trustManagers = {myX509TrustManager};
        sslContext.init(null, trustManagers, null);


        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        conn.setSSLSocketFactory(socketFactory);


        InputStream inputStream;
        int status = conn.getResponseCode();

        if (status != HttpURLConnection.HTTP_OK) {
            inputStream = conn.getErrorStream();
        } else {
            inputStream = conn.getInputStream();
        }
        byte[] bytes = new byte[1024];
        int read = inputStream.read(bytes);
        String result = new String(bytes, 0, read);

        Log.d("MMMMM", "getSafeFromServerSample: " + result);

        inputStream.close();

    }

    X509Certificate getX509Certificate(Context context, String cerName) throws IOException, CertificateException {

        InputStream in = context.getAssets().open(cerName);

        CertificateFactory instance = CertificateFactory.getInstance("X.509");

        X509Certificate certificate = (X509Certificate) instance.generateCertificate(in);

        return certificate;
    }
}

/**
 * 自行验证签名的方式
 */
class MyX509TrustManager implements X509TrustManager {

    //如果需要对证书进行校验，需要这里去实现，如果不实现的话是不安全
    X509Certificate mX509Certificate;
    X509Certificate ca;

    public MyX509TrustManager(X509Certificate mX509Certificate, X509Certificate ca) {
        this.mX509Certificate = mX509Certificate;
        this.ca = ca;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null) {
            throw new IllegalArgumentException("checkServerTrusted:X509Certificate array is null");
        }

        if (!(chain.length > 0)) {
            throw new IllegalArgumentException("checkServerTrusted:X509Certificate is empty");
        }

        if (!(null != authType && authType.equalsIgnoreCase("ECDHE_RSA"))) {
            throw new CertificateException("checkServerTrusted:AuthType is not ECDHE_RSA");
        }

        // 下面这样写好像不对, 总是异常. 或者是证书生成有问题
        //Check if certificate send is your CA's
//        if (!chain[0].equals(mX509Certificate)) {
//            try {   //Not your CA's. Check if it has been signed by your CA
//                chain[0].verify(mX509Certificate.getPublicKey());
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//        }


        // 这里总是报错:java.security.SignatureException: error:0407f070:RSA routines:verify_raw:DATA_TOO_LARGE_FOR_MODULUS
        // 是因为Where are you sending it for validation and how are you generating the key? Usually that error is only seen when you're sending the standard 2048bit key somewhere that's expecting a 1024bit key.
        // 是因为在使用 Openssl 生成的 ca 的时候, 指定了 2048, 然后生成服务器的时候, 指定了 1024 时候指定了 2048bit..醉了

        //If we end here certificate is trusted. Check if it has expired.
//        try {
//            chain[0].checkValidity();
//        } catch (Exception e) {
//            throw new CertificateException("Certificate not trusted. It has expired", e);
//        }


        for (X509Certificate certificate : chain) {

            //检查证书是否有效
            certificate.checkValidity();
            PublicKey publicKey = mX509Certificate.getPublicKey();
            try {
                // 尝试针对单个公钥验证链中的所有证书是没有意义的.它们中的大多数都不会被它签名,因此该过程必然会失败,并向调用者抛出异常.
                // 这个没有意义
                // 在这种情况下,受信任的根证书可能是您从文件加载的证书.
                //
                // 你应该做的是：
                //
                // >在链中查找该证书,如果没有找到
                //   >根据此公钥验证链中的最后一个证书,因为这是最顶层的签名者,而且这是您唯一需要信任的证书.其余的人都被他们在链中的各自成员所信任,他们的继承者都不是这个受信任的根证书,(1).
                // >如果在链中找到证书,请验证以前的证书.即由此证书签名的公钥.


                // 好像就是这样写啊, 为啥不对呢.
                // 不知道是不是因为是用 ip 访问的原因.
                // certificate.verify(certificate.getPublicKey());

                // 要用 cert 验证 ca 的 publicKey 这样就对了
                certificate.verify(ca.getPublicKey());
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (SignatureException e) {
                e.printStackTrace();
            }
        }
    }

    @Override

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

}

class SSLTrustAllManager implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

// 锁定证书公钥在apk中
// 也可以用于使用CA机构证书, 并需要手动校验的情况
class PubKeyManager implements X509TrustManager {

    private static String PUB_KEY = "30819f300d06092a864886f70d010101050003818d0030818902818100a7e073ee3286804d3b2b313a4170465b4da2059cf2fddc300a9691eef72d7c6cae02eda6707bbbfc19555571800ac012efe0db47f63a58d9cd0d4902503ba93dfd2208f67a7c31374cd63663c68cb23913ba29e34fe60b70de31edc65252101780224a452868a5bcff2f7387b6f632656d7810e1ab3a307f42bb46ed77e5895f0203010001";


    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        //1. 对服务端返回的证书做判空处理
        //2. 校验加密算法种类
        //3. 检查证书是否在有效期内
        //4. 校验公钥字符串是否相同

        if (chain == null) {
            throw new IllegalArgumentException("checkServerTrusted:X509Certificate array is null");
        }

        if (!(chain.length > 0)) {
            throw new IllegalArgumentException("checkServerTrusted:X509Certificate is empty");
        }

        if (!(null != authType && authType.equalsIgnoreCase("ECDHE_RSA"))) {
            throw new CertificateException("checkServerTrusted:AuthType is not ECDHE_RSA");
        }

        for (X509Certificate cert : chain) {
            try {
                //3.检查证书是否在有效期内
                cert.checkValidity();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


        // 对比公钥是否相同
        RSAPublicKey pubkey = (RSAPublicKey) chain[0].getPublicKey();

        String encoded = new BigInteger(1 /* positive */, pubkey.getEncoded()).toString(16);


        final boolean expected = PUB_KEY.equalsIgnoreCase(encoded);

        if (!expected) {
            throw new CertificateException("checkServerTrusted:Expected public key: "
                    + PUB_KEY + ",got public key:" + encoded);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

}

