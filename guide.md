# HttpHeadersCheck Kullanım Kılavuzu

## Amaç

HttpHeadersCheck, bir web sitesinin veya hedef IP adresinin HTTP yanıt başlıklarını kontrol ederek, bu başlıkların güvenlik ve uyumluluk açısından doğru şekilde yapılandırıldığından emin olmak için kullanılan bir araçtır.

## Kullanım

HttpHeadersCheck, Python programlama dilinde yazılmıştır. Kullanmak için Python'ı bilgisayarınıza yüklemeniz gerekir.

### Windows için Kurulum Kılavuzu

1. Python'ı resmi web sitesinden buradan: https://www.python.org/downloads/windows indirin ve kurun.
    İndirme işlemini tamamladıktan sonra, Python'ın komut satırından erişilebilir olmasını sağlamak için "PATH" seçeneğini işaretlemelisiniz.

2. Kodu GitHub deposundan bilgisayarınıza indirin:

```
git clone https://github.com/istanboolean/HttpHeadersCheck.git
```


3. Kodu bir dizine çıkartın:

```
cd HttpHeadersCheck
```

4. Gerekli Python paketlerini yükleyin:

```
pip install -r requirements.txt
```

5. Programı başlatın:

```
python httpcheck.py
```

### Linux için Kurulum Kılavuzu

1. Birçok Linux dağıtımı Python'ı varsayılan olarak içerir. Ancak yüklü değilse, terminali açın ve aşağıdaki komutla Python'ı yükleyin:

```
sudo apt-get install python3
```

2. Kodu GitHub deposundan bilgisayarınıza indirin:

```
git clone https://github.com/istanboolean/HttpHeadersCheck.git
```

Bu komut, kodun bulunduğu klasörü bilgisayarınıza indirecektir.

3. Kodu bir dizine çıkartın:

```
cd HttpHeadersCheck
```

4. Gerekli Python paketlerini yükleyin:

```
pip3 install -r requirements.txt
```

5. Programı başlatın:

```
python3 httpcheck.py
```

### Linux için Ek Adım

Linux'ta "chmod +x python3 httpcheck.py" komutunu çalıştırarak, "httpcheck.py" dosyasının çalıştırılabilir hale getirilmesi gerekebilir.

```
chmod +x python3 httpcheck.py
```
```
python3 httpcheck.py -h
```



### Kullanım Örnekleri

* python3 httpcheck.py -d www.example.com: Belirtilen domain için HTTP başlıklarını kontrol eder.
* python3 httpcheck.py -t 192.168.1.1: Belirtilen IP adresi için HTTP başlıklarını kontrol eder.
* python3 httpcheck.py -d www.example.com -c Server Date: Belirtilen başlıkları kontrol eder.
* python3 httpcheck.py -d example.com -C: Tüm HTTP başlıklarını kontrol eder.

  
HttpHeadersCheck, aşağıdakiler gibi çeşitli başlıkları kontrol edebilir:

* X-Frame-Options
* Content-Security-Policy
* Referrer-Policy
* Strict-Transport-Security
* HTTP Strict Transport Security
* X-Content-Type-Options
* X-XSS-Protection
* Cache-Control

**Örneğin:**

Bir web sitesinin X-Frame-Options başlığının yapılandırıldığından emin olmak için, aşağıdaki komutu kullanabilirsiniz:

```
python httpcheck.py -d https://www.example.com -C X-Frame-Options
```

Bu komut, web sitesinin X-Frame-Options başlığının yapılandırılmış olup olmadığını kontrol edecektir.

### Hedef Kitle

HttpHeadersCheck, aşağıdakiler gibi çeşitli kullanıcılar tarafından kullanılabilir:

* Web sitelerinin ve hedef IP adreslerinin sahipleri
* Web sitesi güvenlik uzmanları
* Uyumluluk uzmanları

### Özet

HttpHeadersCheck, web sitelerinizi ve hedef IP adreslerinizi daha güvenli hale getirmek için faydalı bir araçtır. Tool'u kullanarak, güvenlik açıklarını tespit edebilir ve bunlara karşı önlemler alabilirsiniz.

**HttpHeadersCheck Betik Açıklaması**

Bu betik, bir web sitesinin veya hedef IP adresinin HTTP yanıt başlıklarını kontrol etmek için kullanılır. Bu başlıklar, web uygulamalarının güvenliğini artırmak için kullanılır.

**Modüller ve Kütüphaneler**

Kodun başlangıcında, kullanılacak modüller ve kütüphaneler içe aktarılır. Bu modüller ve kütüphaneler, kodun işlevselliğini artırmak ve HTTP başlıklarını sorgulamak için kullanılır. İşte bu modüllerin açıklamaları:

* **argparse:** Komut satırı argümanlarını işlemek için kullanılır. Kullanıcının kodu çalıştırırken sağladığı parametreleri alır.
* **rich:** Zengin metinli çıktılar oluşturmak için kullanılır. Bu, kullanıcı dostu bir arayüz sunar.
* **requests:** HTTP istekleri göndermek için kullanılır. İlgili web sitesinden yanıt alır.
* **ipaddress:** IP adreslerini işlemek için kullanılır.
* **urllib3:** SSL sertifikası doğrulamasını devre dışı bırakmak için kullanılır. SSL hatalarını engellemeye yardımcı olur.

**Başlık Tanımlamaları ve Öneriler**

security_headers adında bir sözlük tanımlanır. Bu sözlük, çeşitli güvenlik başlıklarını ve her başlık için varsayılan değerleri ile açıklamalarını içerir. Bu başlıklar, web sitelerinin güvenliğini artırmak için kullanılır. Her başlık, adı, varsayılan değeri ve açıklamasıyla birlikte belirtilir.

**Argümanların Tanımlanması**

argparse modülü kullanılarak, kullanıcıdan alınacak komut satırı argümanları tanımlanır. Kullanıcı, komut satırından hangi domain veya hedef IP adresi üzerinde çalışmak istediğini, hangi HTTP başlıklarını kontrol etmek istediğini belirtebilir.

**Argümanların İşlenmesi**

Kullanıcı tarafından sağlanan argümanlar işlenir ve args adlı bir değişkende saklanır. Bu, kullanıcının kodu nasıl çalıştırmak istediğini ve hangi işlemleri yapmak istediğini belirtir.

**normalize_url Fonksiyonu**

normalize_url adlı bir fonksiyon tanımlanır. Bu fonksiyon, kullanıcının verdiği URL'yi düzgün bir formata getirir. Eğer kullanıcı bir IP adresi sağlamışsa, bu IP adresini "https://" ile tamamlar. Aksi takdirde, verilen URL'nin başına "https://" ekler.

**HTTP Yanıt Başlıklarını Alma**

get_response_headers fonksiyonu, belirtilen URL'ye bir HTTP GET isteği gönderir ve yanıtın başlıklarını alır. Bu başlıklar daha sonra kontrol edilmek üzere kullanılır.

**Başlıkları Kontrol Etme**

check_headers fonksiyonu, belirtilen HTTP başlıklarını ve yanıtları karşılaştırarak eksik veya yanlış yapılandırılmış başlıkları belirler. Bu fonksiyon, başlıkların durumunu iki liste halinde döndürür: headers_found (başlık bulundu) ve headers_not_found (başlık bulunamadı).

**Başlık Açıklamalarını Alma**

get_header_description fonksiyonu, belirtilen başlığın açıklamasını döndürür. Eğer başlık belirtilmemişse veya belirtilen başlık security_headers sözlüğünde bulunamazsa, bir açıklama yerine "Bu başlık için açıklama bulunamadı." mesajını döndürür.

**Ana İşlev**

main fonksiyonu, kodun ana işleyişini yürütür. Kullanıcıdan alınan argümanları işler, belirtilen URL üzerinde HTTP yanıt başlıklarını alır ve başlıkları kontrol eder. Sonuçları kullanıcı dostu bir şekilde zengin metin formatında görüntüler.

**Kodun Çalıştırılması**

if name == "main" bloğu, kodun doğrudan çalıştırılmasını sağlar. Eğer bu dosya doğrudan çalıştırılıyorsa (başka bir dosya tarafından içe aktarılmıyorsa), main fonksiyonunu çağırarak kodun başlamasını sağlar.

Bu, kodun bir özetini sunar ve önemli hususları vurgular. 


**Komut Satırı Parametreleri:**

* -d veya --domain: Kontrol edilecek olan domain adını belirtir.
* -t veya --target-ip: Kontrol edilecek olan hedef IP adresini belirtir.
* -c veya --check: Kontrol edilecek HTTP başlıklarını belirtmek için kullanılır.
* -C veya --check-all: Tüm HTTP başlıklarını kontrol etmek için kullanılır.

**Kullanım Örnekleri:**

* python3 httpcheck.py -d www.example.com: Belirtilen domain için HTTP başlıklarını kontrol eder.
* python3 httpcheck.py -t 192.168.1.1: Belirtilen IP adresi için HTTP başlıklarını kontrol eder.
* python3 httpcheck.py -d www.example.com -c Server Date: Belirtilen başlıkları kontrol eder.
* python3 httpcheck.py -d example.com -C: Tüm HTTP başlıklarını kontrol eder.

**Bu betik, bir web sitesinin güvenlik başlıklarını ve diğer HTTP başlıklarını kontrol etmek için kullanışlı bir araçtır ve bu başlıkların doğru bir şekilde yapılandırıldığından emin olmanıza yardımcı olabilir.**
