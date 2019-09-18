  // Node.js 使用接口鉴权 V3  POST 请求 faceid 的 IdCardVerification 接口示例
  // 写有 ocr 处均为服务名称，慧眼用 faceid ， ocr 文字识别用 ocr
  // GET 请求的请求包大小不得超过 32KB。POST 请求使用签名方法为 HmacSHA1、HmacSHA256 时不得超过1MB 。POST 请求使用签名方法为 TC3-HMAC-SHA256 时支持 10MB。 这里使用 POST 示例 。 
  // created by v_hyphe 2019-09-12

  /**
   * 详细文档需要参考 ：
   * 1. 请求结构：https://cloud.tencent.com/document/product/1007/31322
   * 2. 公共参数：https://cloud.tencent.com/document/product/1007/31323
   * 3. 接口鉴权v3：https://cloud.tencent.com/document/product/1007/31324
   * 4. 接口鉴权：https://cloud.tencent.com/document/product/1007/31325
   * 5. 返回结果: https://cloud.tencent.com/document/product/1007/31326
   */
  const crypto = require('crypto');
  const https = require('https');
  
  // 1. 拼接规范请求串 CanonicalRequest
  var HTTPRequestMethod = 'POST'; // HTTP 请求方法（GET、POST ）。此示例取值为 POST
  var CanonicalURI = '/'; // URI 参数，API 3.0 固定为正斜杠（/）
  var CanonicalQueryString = ""; // POST请求时为空,对于 GET 请求，则为 URL 中问号（?）后面的字符串内容(注意: canonicalQueryString需要经过 URL 编码)
  var CanonicalHeaders = "content-type:application/json\nhost:faceid.tencentcloudapi.com\n";
  /**
   * 参与签名的头部信息，content-type 和 host 为必选头部，
   * 其中 host 指接口请求域名 POST 请求支持的 Content-Type 类型有：
   * 1. application/json（推荐），必须使用 TC3-HMAC-SHA256 签名方法。； 
   * 2. application/x-www-form-urlencoded，必须使用 HmacSHA1 或 HmacSHA256 签名方法。； 
   * 3. multipart/form-data（仅部分接口支持），必须使用 TC3-HMAC-SHA256 签名方法。
   */
  var SignedHeaders = "content-type;host";
  /**
   * 参与签名的头部信息的 key，可以说明此次请求都有哪些头部参与了签名，和 CanonicalHeaders 包含的头部内容是一一对应的。
   * content-type 和 host 为必选头部 。 
   * 注意： 
   * 1. 头部 key 统一转成小写； 
   * 2. 多个头部 key（小写）按照 ASCII 升序进行拼接，并且以分号（;）分隔 。 
   */
  // 传入需要做 HTTP 请求的正文 body
  var payload = {
      "IdCard":"440882199600110011", 
      "Name":"aaa"
  }
  var HashedRequestPayload = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex'); // 哈希加密后的请求字符串 此示例结果是75e8c07a78df3e4669c4cae256a5276f64f6101ef932267930ed6b505d52013f
  console.log(HashedRequestPayload)
  // 拼接
  var CanonicalRequest =  HTTPRequestMethod + '\n' +
    CanonicalURI + '\n' +
    CanonicalQueryString + '\n' +
    CanonicalHeaders + '\n' +
    SignedHeaders + '\n' +
    HashedRequestPayload;
  console.log('1. 拼接规范请求串');
  console.log(CanonicalRequest);
  console.log('\n');

  // 2. 拼接待签名字符串
  var Algorithm = "TC3-HMAC-SHA256"; // 签名算法，目前固定为 TC3-HMAC-SHA256
  var RequestTimestamp = Math.round(new Date().getTime()/1000) + ""; // 请求时间戳，即请求头部的公共参数 X-TC-Timestamp 取值，取当前时间 UNIX 时间戳，精确到秒
  var t = new Date();
  var date = t.toISOString().substr(0, 10); // 计算 Date 日期   date = "2019-09-12"
  /**
   * Date 必须从时间戳 X-TC-Timestamp 计算得到，且时区为 UTC+0。
   * 如果加入系统本地时区信息，例如东八区，将导致白天和晚上调用成功，但是凌晨时调用必定失败。
   * 假设时间戳为 1551113065，在东八区的时间是 2019-02-26 00:44:25，但是计算得到的 Date 取 UTC+0 的日期应为 2019-02-25，而不是 2019-02-26。
   * Timestamp 必须是当前系统时间，且需确保系统时间和标准时间是同步的，如果相差超过五分钟则必定失败。
   * 如果长时间不和标准时间同步，可能导致运行一段时间后，请求必定失败，返回签名过期错误。
   */
  var CredentialScope = date + "/faceid/tc3_request"; 
  /**
   *  拼接 CredentialScope 凭证范围，格式为 Date/service/tc3_request ， 
   * service 为服务名，慧眼用 faceid ， OCR 文字识别用 ocr
   */

   // 将第一步拼接得到的 CanonicalRequest 再次进行哈希加密
  var HashedCanonicalRequest = crypto.createHash('sha256').update(CanonicalRequest).digest('hex'); 
  // 拼接
  var StringToSign = Algorithm + '\n' +
    RequestTimestamp + '\n' +
    CredentialScope + '\n' +
    HashedCanonicalRequest;
  console.log('2. 拼接待签名字符串');
  console.log(StringToSign);
  console.log('\n');

  // 3. 计算签名
  var SecretKey = "8o4GE0YzB5kAKFyVqPnwpZ4TgipVv61f"; // SecretKey, 需要替换为自己的
  var SecretDate = crypto.createHmac('sha256', "TC3"+SecretKey).update(date).digest();
  var SecretService = crypto.createHmac('sha256', SecretDate).update("faceid").digest();
  var SecretSigning = crypto.createHmac('sha256', SecretService).update("tc3_request").digest();
  var Signature = crypto.createHmac('sha256', SecretSigning).update(StringToSign).digest('hex');
  console.log('3. 计算签名');
  console.log(Signature); // 当前计算为 05e5d9d73f6e9c9ced0dc37d6468390edcb9074cccb010bbb19b28d78a92a860
  console.log('\n');

  // 4. 拼接Authorization
  var SecretId = "AKIDDqJadcH3PWWEgGelfKoX1FF0NPBoFpxs"; // // SecretId, 需要替换为自己的
  var Algorithm = "TC3-HMAC-SHA256";
  var Authorization =
    Algorithm + ' ' +
    'Credential=' + SecretId + '/' + CredentialScope + ', ' +
    'SignedHeaders=' + SignedHeaders + ', ' +
    'Signature=' + Signature
  console.log('4. 拼接Authorization');
  console.log(Authorization);
  console.log('\n');
  // TC3-HMAC-SHA256 Credential=AKIDDqJadcH3PWWEgGelfKoX1FF0NPBoFpxs/2019-09-12/faceid/tc3_request, SignedHeaders=content-type;host, Signature=05e5d9d73f6e9c9ced0dc37d6468390edcb9074cccb010bbb19b28d78a92a860

  // 5.发送POST请求
  var post_data = JSON.stringify(payload); 
  var hostname = "faceid.tencentcloudapi.com"
  console.log(RequestTimestamp)
  // https模块 request options配置
  var options = {
      hostname: hostname,
      // port:443,
      path:'/',
      method:'POST',
      json: true,
      headers: {
        "Content-Type": "application/json",
        "Content-Length": post_data.length,
        "Authorization": Authorization,
        "Host": "faceid.tencentcloudapi.com",
        "X-TC-Action": "IdCardVerification",
        "X-TC-Version": "2018-03-01",
        "X-TC-Timestamp": RequestTimestamp,
        "X-TC-Region": "ap-guangzhou"
      }
  };
  // 发起请求
  var reqTemp = https.request(options,function(resTemp) {
      console.log('发起请求')
      console.log('STATUS:' + resTemp.statusCode);
      console.log('HEADERS:' + JSON.stringify(resTemp.headers));
      resTemp.setEncoding('utf8');
      var result = "";
      resTemp.on('data', function (chunk) {
          result += chunk; // 当数据过大时，会分几次传输，都给加到 result 中去
          console.log('BODY:'+ chunk);
          console.log(chunk);
          console.log(typeof(chunk));
          
      });
      resTemp.on('end', function (chunk) {
        console.log('end')
          console.log(result);
		      // 请求得到的数据
      })
  });
  reqTemp.write(post_data);
  reqTemp.on('error', function(e) {
      console.error(e);
  });
