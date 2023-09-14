# İçindekiler

1. [Content Security Policy (CSP)](#content-security-policy)
2. [HTTP Strict Transport Security (HSTS) Header](#http-strict-transport-security-hsts-header)
3. [X-Frame-Options](#x-frame-options)
4. [X-Content-Type-Options Header](#x-content-type-options-header)
5. [X-XSS-Protection Header](#x-xss-protection-header)

---

## Content Security Policy (CSP)

CSP, web sitelerini çeşitli saldırılardan korumak için kullanılan bir güvenlik protokolüdür. Bir CSP, web sitesinin hangi kaynaklardan içerik yükleyebileceğini tanımlayan bir dizi kuraldır. Bu kurallar, web sitesinin kaynaklarını kötü amaçlı yazılım yüklemeleri, kimlik avı saldırıları, cross-site scripting (XSS),  clickjacking vb. güvenlik tehditlerine karşı korumaya yardımcı olur.

CSP, web sunucusu tarafından gönderilen bir HTTP başlığı olarak çalışır. Bu başlık, tarayıcının web sitesi için hangi kaynakları yükleyebileceğini belirten yönergeler içerir.
CSP, bir dizi farklı kurala izin verir. En yaygın kurallar şunlardır:


### Content Security Policy (CSP) - `default-src` Yönergesi ve Değerleri

`default-src` yönergesi, web sitesinin varsayılan kaynaklarını tanımlar. Bu kaynaklar, web sitesinin hangi kaynaklardan JavaScript, CSS, stil sayfaları, resimler ve diğer içerikleri yükleyebileceğini belirtir.

Aşağıda, `default-src` yönergesinin geçerli değerleri alfabetik sırayla listelenmiştir:

Değer	Açıklama	Kullanım Örneği
Content Security Policy (CSP) - default-src Yönergesi ve Değerleri
| Direktif | Açıklama | Kullanım Örneği
|---|---|---|
| "<hash-algorithm>-<base64-value>" | Web sitesinin belirli bir hash değerine sahip satır içi komut dosyalarını beyaz listeye almasına izin verir. | `default-src 'self' 'sha256-1234567890abcdef'`
| 'none' | Web sitesinin belirli bir tür içerik yüklemesini engeller. | `default-src 'none'`
| 'self' | Web sitesinin yalnızca kendi sunucusundan içerik yüklemesine izin verir. | `default-src 'self'`
| 'strict-dynamic' | Bu değer, nonce veya hash'e sahip komut dosyalarından birine verilen güvenin, yüklenen komut dosyaları eşleşmese veya beyaz listede olmasa bile söz konusu nonce/karma komut dosyası tarafından yüklenen tüm komut dosyalarına yayılacağını belirtir. | `default-src 'self' 'nonce-abc123'`
| 'unsafe-eval' | Web sitesinin eval gibi işlevler aracılığıyla kod çalıştırmasına izin verir. | `default-src 'self' 'unsafe-eval'`
| 'unsafe-inline' | Web sitesinin satır içi kod çalıştırmasına izin verir. | `default-src 'self' 'unsafe-inline'`
| <host-source> | Web sitesinin hangi ana bilgisayarlardan içerik yükleyebileceğini tanımlar. | `default-src 'example.com'`
| <scheme-source> | Web sitesinin hangi şemalara sahip kaynaklardan içerik yükleyebileceğini tanımlar. | `default-src 'https:'`
| Eksik ve Hatalı default-src Değerleri |
| '*' | Web sitesinin tüm kaynaklardan içerik yüklemesine izin verir. Bu, güvenlik açısından risklidir. | `default-src '*'`
| 'self' 'unsafe-eval' | Web sitesinin kendi sunucusundan ve eval gibi işlevler aracılığıyla kod çalıştırmasına izin verir. Bu, güvenlik açısından risklidir. | `default-src 'self' 'unsafe-eval'`
| 'self' 'unsafe-inline' | Web sitesinin kendi sunucusundan ve satır içi kod çalıştırmasına izin verir. Bu, güvenlik açısından risklidir. | `default-src 'self' 'unsafe-inline'`

| Direktif | Açıklama |
|---|---|
| script-src | JavaScript kaynaklarının nereden yüklenebileceğini belirler. |
| object-src | Eklentlerin nereden yüklenebileceğini ve çalıştırılabileceğini belirler. |
| style-src | CSS veya stil etiketlerinin nereden yüklenebileceğini belirler. |
| img-src | Resimlerin nereden yüklenebileceğini belirler. |
| media-src | Ses ve video kaynaklarının (örneğin, HTML5 <audio>) geçerli kaynaklarını tanımlar. |
| frame-src | Çerçeveleri yüklemek için geçerli kaynakları belirler. |
| font-src | Yazı tiplerinin nereden yüklenebileceğini belirler. |
| connect-src | Web uygulamasının XMLHttpRequest, WebSocket veya EventSource aracılığıyla bağlantı yapmasına izin verilen kaynakları belirler. |
| sandbox | İçeriği bir güvenlik kum havuzu içine "güvenli" bir şekilde gömme politikasını belirtir. |
| report-uri | Tarayıcıya politika ihlallerini bir URI'ye bildirmesini söyler. |
| report-to | report-uri'nin yerine kullanılan ve CSP sürüm 3'te ortaya çıkan bir politika ihlali raporu göndermek için kullanılan bir yöntemdir. |
| base-uri | Belge taban URL'sini belirleyen ve HTML belgesi içindeki tüm göreceli URL'lerin temelini belirleyen URL'leri sınırlar. Yalnızca CSP sürüm 2 ve sonrasında kullanılabilir. |
| child-src | Web işçileri ve <frame> ve <iframe> gibi öğeler kullanılarak yüklenen içerik için geçerli kaynakları belirler. Sürüm 3'te kullanımdan kaldırıldı. |
| form-action | HTML <form> eylemi olarak kullanılabilecek geçerli URL'leri belirler. Yalnızca CSP sürüm 2 ve sonrasında kullanılabilir. |
| frame-ancestors | Bir kaynağın çerçevelenme kaynaklarını belirler. Yalnızca CSP sürüm 2 ve sonrasında kullanılabilir. |
| plugin-types | <object> ve <embed> ile çağrılan eklentiler için geçerli MIME tiplerini belirler. Yalnızca CSP sürüm 2 ve sonrasında kullanılabilir. |
| worker-src | Worker, SharedWorker veya ServiceWorker olarak yüklenebilecek URL'leri sınırlar. Yalnızca CSP sürüm 3 ve sonrasında kullanılabilir. |
| manifest-src | Uygulamanın manifest dosyasının nereden yüklenebileceğini sınırlar. Yalnızca CSP sürüm 3 ve sonrasında kullanılabilir. |

# Cross-site scripting (XSS) koruması için bazı CSP yönergeleri

### script-src

| Yönerge | Açıklama | Örnek |
|---|---|---|
| script-src | JavaScript kaynaklarının nereden yüklenebileceğini belirler. | `script-src 'self'` |
| script-src-elem | `script` ve `link` öğelerinden yüklenen komut dosyalarının nereden yüklenebileceğini belirler. | `script-src-elem 'self' https://example.com` |
| script-src-attr | `img` öğesinin `href` özniteliğinden yüklenen komut dosyalarının nereden yüklenebileceğini belirler. | `script-src-attr 'self' https://example.com` |

### img-src

| Yönerge | Açıklama | Örnek |
|---|---|---|
| img-src | Resimlerin nereden yüklenebileceğini belirler. | `img-src 'self'` |
| img-src-elem | `img` öğelerinden yüklenen görüntülerin nereden yüklenebileceğini belirler. | `img-src-elem 'self' https://example.com` |
| img-src-attr | `img` öğesinin `src` özniteliğinden yüklenen görüntülerin nereden yüklenebileceğini belirler. | `img-src-attr 'self' https://example.com` |

### frame-src

| Yönerge | Açıklama | Örnek |
|---|---|---|
| frame-src | Çerçevelerin nereden yüklenebileceğini belirler. | `frame-src 'self'` |
| frame-src-elem | `iframe` öğelerinden yüklenen çerçevelerin nereden yüklenebileceğini belirler. | `frame-src-elem 'self' https://example.com` |
| frame-src-attr | `img` öğesinin `src` özniteliğinden yüklenen çerçevelerin nereden yüklenebileceğini belirler. | `frame-src-attr 'self' https://example.com` |

### object-src

| Yönerge | Açıklama | Örnek |
|---|---|---|
| object-src | Nesnelerin nereden yüklenebileceğini belirler. | `object-src 'self'` |
| object-src-elem | `object` ve `embed` öğelerinden yüklenen nesnelerin nereden yüklenebileceğini belirler. | `object-src-elem 'self' https://example.com` |
| object-src-attr | `img` öğesinin `src` özniteliğinden yüklenen nesnelerin nereden yüklenebileceğini belirler. | `object-src-attr 'self' https://example.com` |

### HTTP Strict Transport Security (HSTS) Header

HSTS header, web sitesinin tüm iletişiminin yalnızca HTTPS protokolü üzerinden gerçekleşmesini sağlayan bir güvenlik başlığıdır. ...

# Strict-Transport-Security (HSTS) yönergeleri

| Yönerge | Açıklama | Örnek |
|---|---|---|
| max-age | Tarayıcının HSTS politikasını ne kadar süreyle hatırlaması gerektiğini belirtir. Bu direktif, saniye cinsinden bir sayı olarak belirtilir.Tarayıcının HSTS politikasını 1 yıl (31536000 saniye) boyunca hatırlamasını sağlar.| `max-age=31536000` |
| includeSubDomains | Bu isteğe bağlı direktif, HSTS politikasının bu HSTS hostunun yanı sıra hostun alan adının tüm alt alanları için de geçerli olduğunu gösterir. | `max-age=31536000; includeSubDomains` |
| preload | Bu direktif, alan adının tarayıcıya bilinen bir HSTS hostu olarak ön yüklenebileceğini gösterir. Bu, tarayıcının web sitenizi açmadan önce HSTS politikasını öğrenmesini sağlar. | `max-age=31536000; includeSubDomains; preload` |




# X-Frame-Options Header

X-Frame-Options header, web sitesinin iframe içinde görüntülenip görüntülenmeyeceğini gösteren bir güvenlik başlığıdır. Bu header'ı etkinleştirerek, web sitenizin yalnızca güvenilir kaynaklardan gelen iframe'lerde görüntülenmesini sağlayabilirsiniz. Bu, clickjacking saldırılarına karşı koruma sağlayabilir.

## Clickjacking nedir?

Clickjacking, kullanıcıların farkında olmadan kötü amaçlı bir web sitesine giriş yapmalarına veya eylemler gerçekleştirmelerine neden olan bir saldırı türüdür. Bu saldırılar, kullanıcıların tıklamalarını sahte bir web sitesine yönlendirmek için iframe'ler kullanılarak gerçekleştirilir.
| Yönerge | Açıklama | Örnek |
|---|---|---|
| DENY | Web sitesi hiçbir zaman iframe içinde görüntülenemez. Bu, clickjacking saldırılarına karşı en güçlü korumayı sağlar. | `Header always set X-Frame-Options DENY` |
| SAMEORIGIN | Web sitesi yalnızca aynı alan adı veya alt alan adı içinde iframe içinde görüntülenebilir. Bu, clickjacking saldırılarına karşı orta düzeyde koruma sağlar. | `Header always set X-Frame-Options SAMEORIGIN` |
| ALLOW-FROM | Web sitesi yalnızca belirtilen URL'lerden gelen iframe içinde görüntülenebilir. Bu, clickjacking saldırılarına karşı en az düzeyde koruma sağlar. | `Header always set X-Frame-Options ALLOW-FROM https://example.com` |


## X-Frame-Options header'ı nasıl etkinleştiririm?

X-Frame-Options header'ı web sunucunuzun ayarlarında etkinleştirebilirsiniz. 


# X-Content-Type-Options header

X-Content-Type-Options header, web sunucusunun HTTP yanıtlarına eklediği bir güvenlik başlığıdır. Bu header, tarayıcıların web sitesinin yanıtlarında bulunan içerik türlerini değiştirmesini engellemek için kullanılır.

**İçerik sahteciliği saldırıları nedir?**

İçerik sahteciliği saldırıları, saldırganların kullanıcıları kandırmak için web sitelerini manipüle etmek için kullandığı bir tür sosyal mühendislik saldırısıdır. Bu saldırılarda, saldırganlar, web sitesinin yanıtlarında bulunan içerik türlerini değiştirerek, kullanıcıları zararlı içeriklere yönlendirmeye çalışırlar.

**X-Content-Type-Options header'ın faydaları**

X-Content-Type-Options header'ı kullanmak, web sitenizi içerik sahteciliği saldırılarına karşı korumanın etkili bir yoludur. Bu header'ı kullanarak, tarayıcıların web sitenizin yanıtlarında bulunan içerik türlerini değiştirmesini engelleyebilir ve böylece kullanıcıları zararlı içeriklere yönlendirilmekten koruyabilirsiniz.

**X-Content-Type-Options header'ın yönergeleri**

X-Content-Type-Options header'ın iki yönergesi vardır:

* **nosniff:** Tarayıcıların web sitesinin yanıtlarında bulunan içerik türlerini değiştirmesini engeller. Bu, içerik sahteciliği saldırılarına karşı en güçlü korumayı sağlar.
* **sniff:** Tarayıcıların web sitesinin yanıtlarında bulunan içerik türlerini değiştirmesine izin verir. Bu, web sitenizin bazı özelliklerini kullanmanıza izin verir, ancak içerik sahteciliği saldırılarına karşı daha az koruma sağlar.

**X-Content-Type-Options header'ı nasıl etkinleştiririm?**

X-Content-Type-Options header'ı etkinleştirmek için web sunucunuzun ayarlarında aşağıdaki satırı ekleyebilirsiniz:
| Yönerge | Açıklama | Örnek |
|---|---|---|
| nosniff | Tarayıcıların web sitesinin yanıtlarında bulunan içerik türlerini değiştirmesini engeller. Bu, içerik sahteciliği saldırılarına karşı en güçlü korumayı sağlar. | `Header always set X-Content-Type-Options nosniff` |



# X-XSS-Protection header

X-XSS-Protection header, web sunucusunun HTTP yanıtlarına eklediği bir güvenlik başlığıdır. Bu header, tarayıcıların web sitesinin yanıtlarında bulunan XSS (Cross-Site Scripting) saldırılarını önlemek için kullandığı bir güvenlik önlemidir.

**XSS saldırıları nedir?**

XSS saldırıları, saldırganların kullanıcıları kandırmak için web sitelerini manipüle etmek için kullandığı bir tür web saldırısıdır. Bu saldırılarda, saldırganlar, web sitesinin yanıtlarında bulunan JavaScript kodunu değiştirerek, kullanıcıları zararlı bir web sitesine yönlendirmeye çalışırlar.

**X-XSS-Protection header'ın faydaları**

X-XSS-Protection header'ı kullanmak, web sitenizi XSS saldırılarına karşı korumanın etkili bir yoludur. Bu header'ı kullanarak, tarayıcıların web sitenizin yanıtlarında bulunan XSS saldırılarını önlemesini sağlayabilirsiniz.


X-XSS-Protection header'ın dört yönergesi vardır:

* **0:** Tarayıcı, XSS saldırılarını önlemek için herhangi bir önlem almaz. Bu, XSS saldırılarına karşı en az korumayı sağlar.
* **1:** Tarayıcı, XSS saldırılarını önlemek için bazı önlemler alır. Bu, web sitenizi XSS saldırılarına karşı korumak için etkili bir yoldur.
* **1; mode=block:** Tarayıcı, XSS saldırılarını önlemek için daha güçlü önlemler alır. Bu, web sitenizi XSS saldırılarına karşı en iyi şekilde korumak için en iyi yoldur.
* **1; report=uri:** Tarayıcı, XSS saldırılarını önlemek için daha güçlü önlemler alır ve ayrıca tespit edilen XSS saldırıları hakkında bir rapor gönderir.

**Yönergelerin örnekleri**

| Yönerge | Açıklama | Örnek |
|---|---|---|
| **0** | Tarayıcı, XSS saldırılarını önlemek için herhangi bir önlem almaz. Bu, XSS saldırılarına karşı en az korumayı sağlar. | `Header always set X-XSS-Protection "0"` |
| **1** | Tarayıcı, XSS saldırılarını önlemek için bazı önlemler alır. Bu, web sitenizi XSS saldırılarına karşı korumak için etkili bir yoldur. | `Header always set X-XSS-Protection "1"` |
| **1; mode=block** | Tarayıcı, XSS saldırılarını önlemek için daha güçlü önlemler alır. Bu, web sitenizi XSS saldırılarına karşı en iyi şekilde korumak için en iyi yoldur. | `Header always set X-XSS-Protection "1; mode=block"` |
| **1; report=uri** | Tarayıcı, XSS saldırılarını önlemek için daha güçlü önlemler alır ve ayrıca tespit edilen XSS saldırıları hakkında bir rapor gönderir. Bu rapor, saldırgan tarafından kullanılan XSS saldırısının türü ve konumu hakkında bilgi içerecektir. | `Header always set X-XSS-Protection "1; report=/path/to/report"` |

