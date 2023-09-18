# HTTP SECURITY HEADERS
HTTP güvenlik başlıkları (HTTP security headers), web uygulamalarını güvenlik açıklarına karşı korumak için kullanılan HTTP başlıklarıdır. Bu başlıklar, web tarayıcılara ve web sunucularına nasıl davranmaları gerektiğini söyler.
HTTP güvenlik başlıkları hakkında daha fazla bilgi için aşağıdaki kaynaklara bakabilirsiniz:

* OWASP HTTP Security Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
* Mozilla Developer Network - HTTP security headers: https://developer.mozilla.org/en-US/docs/Web/Security
* Google Developers - HTTP security headers: https://www.searchenginejournal.com/http-security-headers/415404/

# İçindekiler

1. [Content Security Policy (CSP)](#content-security-policy)
2. [HTTP Strict Transport Security (HSTS) Header](#http-strict-transport-security-hsts-header)
3. [X-Frame-Options](#x-frame-options)
4. [X-Content-Type-Options Header](#x-content-type-options-header)
5. [X-XSS-Protection Header](#x-xss-protection-header)
6. [Referrer-Policy Header](#-referrer-policy-header)
7. [Feature-Policy Header](#-feature-policy-header)
8. [Content-Security-Policy-Report-Only](content-security-policy-report-only)
---
# 1 - X-Content-Type-Options

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

# 2 - X-Frame-Options Header

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

# 3 - HTTP Strict Transport Security (HSTS) Header

HTTP Strict Transport Security (HSTS), bir web sitesinin yalnızca HTTPS üzerinden erişilebilmesini sağlamak için kullanılan bir güvenlik önlemidir. HSTS başlığı, bir web sitesinin HTTP yanıtında gönderilir ve tarayıcıdan, siteye yalnızca HTTPS üzerinden erişmesini ister.

**Örnek:**

** Strict-Transport-Security: max-age=31536000; includeSubDomains; preload **

**Açıklama:**
Bu, tarayıcının sitenize yalnızca HTTPS üzerinden erişmesini ve ayrıca sitenize bağlı tüm alt etki alanlarını da kapsamasını sağlar. Ayrıca, tarayıcının sitenizi güvenilir bir kaynak olarak işaretlemesini sağlar.

### Strict-Transport-Security (HSTS) yönergeleri

| Yönerge | Açıklama | Örnek |
|---|---|---|
| max-age | Tarayıcının HSTS politikasını ne kadar süreyle hatırlaması gerektiğini belirtir. Bu direktif, saniye cinsinden bir sayı olarak belirtilir.Tarayıcının HSTS politikasını 1 yıl (31536000 saniye) boyunca hatırlamasını sağlar.| `max-age=31536000` |
| includeSubDomains | Bu isteğe bağlı direktif, HSTS politikasının bu HSTS hostunun yanı sıra hostun alan adının tüm alt alanları için de geçerli olduğunu gösterir. | `max-age=31536000; includeSubDomains` |
| preload | Bu direktif, alan adının tarayıcıya bilinen bir HSTS hostu olarak ön yüklenebileceğini gösterir. Bu, tarayıcının web sitenizi açmadan önce HSTS politikasını öğrenmesini sağlar. | `max-age=31536000; includeSubDomains; preload` |


# 4 - Content Security Policy (CSP)

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

### Cross-site scripting (XSS) koruması için bazı CSP yönergeleri

#### script-src

| Yönerge | Açıklama | Örnek |
|---|---|---|
| script-src | JavaScript kaynaklarının nereden yüklenebileceğini belirler. | `script-src 'self'` |
| script-src-elem | `script` ve `link` öğelerinden yüklenen komut dosyalarının nereden yüklenebileceğini belirler. | `script-src-elem 'self' https://example.com` |
| script-src-attr | `img` öğesinin `href` özniteliğinden yüklenen komut dosyalarının nereden yüklenebileceğini belirler. | `script-src-attr 'self' https://example.com` |

#### img-src

| Yönerge | Açıklama | Örnek |
|---|---|---|
| img-src | Resimlerin nereden yüklenebileceğini belirler. | `img-src 'self'` |
| img-src-elem | `img` öğelerinden yüklenen görüntülerin nereden yüklenebileceğini belirler. | `img-src-elem 'self' https://example.com` |
| img-src-attr | `img` öğesinin `src` özniteliğinden yüklenen görüntülerin nereden yüklenebileceğini belirler. | `img-src-attr 'self' https://example.com` |

#### frame-src

| Yönerge | Açıklama | Örnek |
|---|---|---|
| frame-src | Çerçevelerin nereden yüklenebileceğini belirler. | `frame-src 'self'` |
| frame-src-elem | `iframe` öğelerinden yüklenen çerçevelerin nereden yüklenebileceğini belirler. | `frame-src-elem 'self' https://example.com` |
| frame-src-attr | `img` öğesinin `src` özniteliğinden yüklenen çerçevelerin nereden yüklenebileceğini belirler. | `frame-src-attr 'self' https://example.com` |

#### object-src

| Yönerge | Açıklama | Örnek |
|---|---|---|
| object-src | Nesnelerin nereden yüklenebileceğini belirler. | `object-src 'self'` |
| object-src-elem | `object` ve `embed` öğelerinden yüklenen nesnelerin nereden yüklenebileceğini belirler. | `object-src-elem 'self' https://example.com` |
| object-src-attr | `img` öğesinin `src` özniteliğinden yüklenen nesnelerin nereden yüklenebileceğini belirler. | `object-src-attr 'self' https://example.com` |

# 5 - X-XSS-Protection header

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

# 6 - Referrer-Policy

Referrer-Policy, web tarayıcılarında kullanılan bir HTTP başlığıdır. Web sayfalarının başka kaynaklara olan yönlendirmelerinin nasıl işlenmesi gerektiğini belirler.

**Yaygın yönergeler:**

* **no-referrer:**  Bu, web sitesinin referans bilgisini tamamen engelleyeceğini belirtir. Bu, bir kullanıcının referans bilgisini kullanarak, kullanıcının ziyaret ettiği diğer web sitelerini spam göndermek veya kullanıcının internette gezinme alışkanlıklarını takip etmek için bir saldırgan tarafından kullanılmasını önlemeye yardımcı olur.
* **origin:** Bu, web sitesinin referans bilgisini yalnızca bağlantının geldiği web sitesine göndereceğini belirtir. Bu, bir saldırgan tarafından kullanılabilecek referans bilgisinin miktarını sınırlamaya yardımcı olur.Sadece kaynağın kökenini (origin) gönderir.
* **same-origin:** Bu, web sitesinin referans bilgisini yalnızca aynı kaynaktan gelen bağlantılara göndereceğini belirtir. Bu, bir saldırgan tarafından kullanılabilecek referans bilgisinin miktarını daha da sınırlamaya yardımcı olur.Sadece aynı kökenden gelen isteklere referrer bilgisi gönderir.
* **strict-origin:** Bu, web sitesinin referans bilgisini yalnızca aynı kaynaktan gelen bağlantılara göndereceğini ve ayrıca bağlantının geldiği web sitesinin protokolünü, sunucu adresini ve portunu da göndereceğini belirtir. Bu, bir saldırgan tarafından kullanılabilecek referans bilgisinin miktarını en aza indirmeye yardımcı olur.Aynı kökenden gelen isteklere referrer bilgisi gönderir, ancak HTTPS'ten HTTP'ye veya HTTP'den HTTPS'e geçişlerde referrer bilgisi göndermez.
* **origin-when-cross-origin:** Bu, web sitesinin referans bilgisini yalnızca farklı kaynaklardan gelen bağlantılara göndereceğini ve ayrıca bağlantının geldiği web sitesinin protokolünü, sunucu adresini ve portunu da göndereceğini belirtir. Bu, bir saldırgan tarafından kullanılabilecek referans bilgisinin miktarını sınırlamaya yardımcı olur.Kısaca kökenden gelen isteklere referrer bilgisi gönderir, ancak farklı bir kökenden gelen isteklere sadece köken bilgisini gönderir.

| Yönerge | Örnek Kullanım | Açıklama |
|---|---|---|
| **no-referrer** | `Referrer-Policy: no-referrer;` | Referans bilgisini tamamen engeller. |
| **origin** | `Referrer-Policy: origin;` | Referans bilgisini yalnızca bağlantının geldiği web sitesine gönderir. |
| **same-origin** | `Referrer-Policy: same-origin;` | Referans bilgisini yalnızca aynı kaynaktan gelen bağlantılara gönderir. |
| **strict-origin** | `Referrer-Policy: strict-origin;` | Referans bilgisini yalnızca aynı kaynaktan gelen bağlantılara gönderir ve ayrıca bağlantının geldiği web sitesinin protokolünü, sunucu adresini ve portunu da gönderir. |
| **origin-when-cross-origin** | `Referrer-Policy: origin-when-cross-origin;` | Referans bilgisini yalnızca farklı kaynaklardan gelen bağlantılara gönderir ve ayrıca bağlantının geldiği web sitesinin protokolünü, sunucu adresini ve portunu da gönderir. |

**Önemi:**

Referrer-Policy kullanmak, özellikle gizlilik ve güvenlik açısından önemlidir. Bu politika, web sayfalarının dış kaynaklara olan bağlantılarını nasıl yönettiğinizi kontrol etmenize yardımcı olur. Özellikle kullanıcıların özel bilgilerini koruma konusunda önemli bir rol oynar.

**Kullanım:**

Referrer-Policy'yi kullanırken, sayfanızın gereksinimlerine ve gizlilik politikalarına uygun bir politika seçmelisiniz. Örneğin, kullanıcıların özel bilgilerini içeren bir sayfadan dış kaynaklara referrer bilgisi göndermemeyi tercih edebilirsiniz. Bu, gizliliği korumanıza yardımcı olabilir.


# 7 - Feature-Policy

Feature-Policy headers, web sitelerinin hangi özelliklerinin kullanılabileceğini kontrol etmek için kullanılan HTTP başlıklarıdır. Bu, web sitelerinin kullanıcıların mahremiyetini ve güvenliğini korumasına yardımcı olabilir.

Feature-Policy headers, aşağıdakiler gibi bir dizi özellik için kullanılabilir:

Hareket sensörleri: Örneğin, bir web sitesi, bir kullanıcının konumunu takip etmek için bir ivmeölçer veya jiroskop kullanabilir.
Kablosuz teknolojiler: Örneğin, bir web sitesi, bir kullanıcıya bildirim göndermek için bir push bildirimi kullanabilir.
Mikrofon ve kamera: Örneğin, bir web sitesi, kullanıcının sesini veya görüntüsünü kaydetmek için bir mikrofon veya kamera kullanabilir.
Feature-Policy headers, aşağıdakileri kullanarak belirli özellikler için izin verebilir veya reddedebilir:

allow: Bir özelliğin kullanılmasına izin verir.
deny: Bir özelliğin kullanılmasına izin vermez.
default: Bir özelliğin kullanımına izin verir, ancak bir kullanıcı veya tarayıcı tarafından devre dışı bırakılabilir.
Feature-Policy headers'ın önemi, web sitelerinin kullanıcıların mahremiyetini ve güvenliğini korumasına yardımcı olmasıdır. Örneğin, bir kullanıcı, bir web sitesinin konumunu takip etmesine izin vermek istemeyebilir. Feature-Policy headers kullanarak, kullanıcılar belirli özellikleri devre dışı bırakabilir ve böylece mahremiyetlerini koruyabilir.

Feature-Policy headers'ın kullanımı, aşağıdaki adımları içerir:

Bir özellik için izin veya ret belirtmek için bir direktif seçin.
Direktifi, web sitesinin kaynak dosyalarına ekleyin.

**Kullanım:**

Feature-Policy: <özellik> < izin veya ret > 

Örnek:

* Feature-Policy: microphone allow      
                Bu ifade, web sitesinin her zaman mikrofonunuza erişmesine izin vereceğini belirtir.

* Feature-Policy: microphone deny      
                Bu ifade, web sitesinin mikrofonunuza erişmesini tamamen reddeder.


**Feature-Policy headers'ın direktifleri şunlardır:**


| Direktif | Açıklama |
|---|---|
| accelerometer | Bir ivmeölçer kullanmaya izin verir veya reddeder. |
| ambient-light-sensor | Bir ortam ışığı sensörü kullanmaya izin verir veya reddeder. |
| autoplay | Otomatik oynatmaya izin verir veya reddeder. |
| camera | Bir kamera kullanmaya izin verir veya reddeder. |
| clipboard-read | Panoya okumaya izin verir veya reddeder. |
| clipboard-write | Panoya yazmaya izin verir veya reddeder. |
| geolocation | Konum belirlemeye izin verir veya reddeder. |
| gyroscope | Bir jiroskop kullanmaya izin verir veya reddeder. |
| magnetometer | Bir manyetometre kullanmaya izin verir veya reddeder. |
| microphone | Bir mikrofon kullanmaya izin verir veya reddeder. |
| midi | MIDI cihazlarını kullanmaya izin verir veya reddeder. |
| payment | Ödeme özelliklerini kullanmaya izin verir veya reddeder. |
| push | Push bildirimleri göndermeye izin verir veya reddeder. |
| screen-orientation | Ekran yönünü değiştirmeye izin verir veya reddeder. |
| speaker | Bir hoparlör kullanmaya izin verir veya reddeder. |
| usb | USB cihazlarını kullanmaya izin verir veya reddeder. |


# 8- Content-Security-Policy-Report-Only

Content-Security-Policy-Report-Only, bir web sitesinin yalnızca CSP ihlallerini rapor etmesini sağlayan bir güvenlik başlığıdır. Bu, CSP'yi devre dışı bırakmadan web sitenizi CSP'ye uyumlu hale getirmenin bir yoludur.
Content-Security-Policy-Report-Only, bir web sitesinin CSP'yi test etmenize veya uyumluluk geliştirmenize olanak tanıyan güvenlik başlığıdır.

* **CSP'yi yalnızca belirli kaynakların yüklenmesine izin vermek için:**

**Örnekler:**

```
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:;
```
Bu, web sitesinin yalnızca kendi kaynaklarından, güvenli olarak dahil edilen koddan, güvenli olarak değerlendirilen koddan, kendi kaynaklarından, güvenli verilerden ve kendi kaynaklarından güvenli bir şekilde dahil edilen yazı tiplerinden kaynak yüklemesine izin verecektir.

* **CSP'yi yalnızca belirli etki alanlarının yüklenmesine izin vermek için:**
  
```
Content-Security-Policy-Report-Only: default-src https://example.com; script-src https://example.com; img-src https://example.com; style-src https://example.com; font-src https://example.com;
```
Bu, web sitesinin yalnızca https://example.com etki alanından kaynak yüklemesine izin verecektir.
