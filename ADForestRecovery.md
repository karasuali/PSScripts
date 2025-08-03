Active Directory Forest Recovery

<img width="736" height="610" alt="image" src="https://github.com/user-attachments/assets/03aae80a-d196-47f8-974d-35cb904d94ac" />

<img width="939" height="542" alt="image" src="https://github.com/user-attachments/assets/8edcaaac-e7ed-4041-b9e3-ebffca140fa7" />

Bu makale de yayınlanan bilgiler, Windows Server 2008 R2, Windows Server 2012 R2, Windows Server 2016 ve Windows Server 2019’a uygulanabilir.
Active Directory’nin backup’ı 2 ayrı backup yazılımı kullanılarak, 2 ayrı Domain Controller makinasından alınmalıdır. Bu backup türününde BMR (Bare Metal Recovery) olması önerilmektedir. Bu makalede Windows Server Backup üzerilen alınan BMR backup-restore işlemi anlatılacaktır.
Bare Metal Recovery (BMR), problem yaşanan sunucu için veri kurtarma ve hızlı yeniden inşa sağlayan bir yedekleme ve geri dönüş tekniğidir. BMR‘nin en önemli karakteristik özelliği Restore yapılacak hedef sunucu üzerinde herhangi bir yazılım veya işletim sistemi ön gereksinimine ihtiyaç duymamasıdır. Bir başka ifadeyle; Windows tabanlı sunucunuz için zamanında almış olduğunuz BMR yedeğini, o an hızlıca temin edebildiğiniz ve farklı donanım özelliklerine sahip bir fiziksel sunucu üzerine dönebilirsiniz.
Active Directory Disaster Recovery süreci domain’de aktif olarak çalışan bir DC kalmadığı zaman uygulanmalıdır. Tüm çalışmalar izole bir network’de yapılmalıdır.
Backup alınan diski ilgili sunucudan disconnect edip restore edilecek DC sunucuya bağlanır

<img width="752" height="709" alt="image" src="https://github.com/user-attachments/assets/38c94bc4-4bb0-42bc-b270-496d3fa59177" />

Restore yapılacak sunucu hazırlandıktan sonra Windows Server ISO ya da DVD ile reboot edilmelidir.

<img width="756" height="561" alt="image" src="https://github.com/user-attachments/assets/b7580b15-d6e1-4e76-ac72-478305088fc8" />

Repair your computer seçilir.

<img width="763" height="564" alt="image" src="https://github.com/user-attachments/assets/fd664939-daf5-4223-be04-bfc13d1e6acd" />

Troubleshoot tıklanır.

<img width="565" height="376" alt="image" src="https://github.com/user-attachments/assets/e3ccf87a-8dec-4d85-9bc0-e73290a224a9" />

System Image Recovery tıklanır.

<img width="576" height="440" alt="image" src="https://github.com/user-attachments/assets/37b77419-ec70-44d3-a862-8a955750d9ea" />

Image seçilir ve next tıklanır.

<img width="532" height="425" alt="image" src="https://github.com/user-attachments/assets/245531ba-45fb-4d4c-99c5-61136cd47095" />

<img width="538" height="433" alt="image" src="https://github.com/user-attachments/assets/d8f95174-93d1-4d2a-a317-978e1194d090" />

Finish ile işlem başlatılır.

<img width="536" height="426" alt="image" src="https://github.com/user-attachments/assets/7ea0b2e8-3c6f-4618-8f74-9b0f7be3bc31" />

<img width="530" height="217" alt="image" src="https://github.com/user-attachments/assets/7d61f089-e5b7-4919-8010-ed5ccd258bf1" />

Sürecin bitmesi beklenir.

<img width="538" height="235" alt="image" src="https://github.com/user-attachments/assets/ceb2cf70-c68d-4ee3-8348-4e4a70bec315" />

<img width="487" height="194" alt="image" src="https://github.com/user-attachments/assets/4852110d-ee0f-4858-b689-105fc5b8d798" />

Domain admin accountu ile oturum açılır. (Oturum açan account Enterprise admin ve Schema Admin grubunun da üyesi olmalıdır.Eğer oturum açan domain admin user’ı bu grup’lara üye değilse üye yapılır ve restart edilir. Ya da RID-500 accountu ile bu işlermler yapılmalıdır.)


<img width="902" height="495" alt="image" src="https://github.com/user-attachments/assets/4a62e4f5-d6be-4d9d-ae57-6414c75a78e8" />

Servislerin kontrolü yapılır. 

<img width="918" height="489" alt="image" src="https://github.com/user-attachments/assets/56100b73-0204-4c99-b4f0-9c395965c02a" />

<img width="354" height="463" alt="image" src="https://github.com/user-attachments/assets/fc033aa3-bab8-404f-b4f3-a4185440ab10" />

IP Yapılandırması control edilir.

<img width="361" height="402" alt="image" src="https://github.com/user-attachments/assets/cb54de12-6833-4a9c-8d7d-190978b30ce4" />

Net share ile sunucu üzerindeki paylaşımlar control edilir.

<img width="855" height="437" alt="image" src="https://github.com/user-attachments/assets/f3a23706-a0b5-4fa7-8d4f-cfbf1b017242" />

ADUC konsolunda Advanced Features enable duruma getirilir.

<img width="688" height="500" alt="image" src="https://github.com/user-attachments/assets/26757ca9-e52c-40bb-b955-a17027640da6" />

Restore’unu yaptığımız DC’nin Sysvol Subscrion’ı seçilir ve sağ tuş ile properties menüsü açılır.

<img width="742" height="516" alt="image" src="https://github.com/user-attachments/assets/a5be1833-66c0-462c-9e3b-35be1aad52ab" />

MsDFSR-Options attribute değeri 1 yapılır.

<img width="540" height="191" alt="image" src="https://github.com/user-attachments/assets/ece178a9-e54b-441a-85d8-23c9dd5292bb" />

DFSR servisi restart edilir ve DFSRDIAG Pollad komutu çalıştırılır.

<img width="772" height="371" alt="image" src="https://github.com/user-attachments/assets/b3b224fb-01ca-479b-812c-b3999f694d06" />

Netdom query fsmo komutu ile FSMO roller’inin aktif olarak çalışmayan bir DC’de olduğu görülüyor ve aşağıdaki komutlar ile roller çalışan DC üzerine taşınır.

<img width="637" height="321" alt="image" src="https://github.com/user-attachments/assets/3a2aff36-9605-424a-8181-4719caf17313" />

<img width="1125" height="270" alt="image" src="https://github.com/user-attachments/assets/db0b5336-02fa-4f20-8e77-e3e0d1beb9d2" />

Netdom query fsmo ile tekrar control sağlanır.

<img width="681" height="188" alt="image" src="https://github.com/user-attachments/assets/c01bb036-a540-4c15-b59f-55696ef9dc95" />

Mevcut DC haricindeki tüm DC’ler metadata cleanup ile temizlenir.

<img width="981" height="535" alt="image" src="https://github.com/user-attachments/assets/e9873a22-14a7-4d0e-8524-4d5c3b2f1b03" />

<img width="987" height="448" alt="image" src="https://github.com/user-attachments/assets/ae183513-52a6-4f11-8a3b-912ab880091c" />

Active Directory Site and Services’dan aktif olmayan DC’ler kaldırılır.

<img width="937" height="470" alt="image" src="https://github.com/user-attachments/assets/e39b36e3-81ec-42a4-a84f-6a2f2743be66" />

DNS servisinden tüm eski DC kayıtları temizlenir.

<img width="430" height="528" alt="image" src="https://github.com/user-attachments/assets/e77daf6a-79b7-46b7-add4-9883453857f5" />

<img width="1125" height="239" alt="image" src="https://github.com/user-attachments/assets/76b43078-2696-45a3-b33f-a9ffa674dc6a" />

Active Directory Users and Computers – System – RID Manager$ – Properties seçilir.

<img width="1040" height="613" alt="image" src="https://github.com/user-attachments/assets/64c2fd8c-7dd2-4f01-9cb1-9282ec730516" />

rIDAvailiblePool değeri 100,000 artırılır.

<img width="555" height="194" alt="image" src="https://github.com/user-attachments/assets/be7e3e74-2465-4115-9487-257918019f4b" />

<img width="567" height="199" alt="image" src="https://github.com/user-attachments/assets/f88adbd0-8e7f-415b-af2e-8ae23ccf015e" />

DCdiag /test:ridmanager /v komutu ile kontrol edilir.

<img width="739" height="181" alt="image" src="https://github.com/user-attachments/assets/772a4b99-650b-41f3-86f6-1640a81f8dbe" />

Yeni bir obje oluşturarak RIDPool kontrolü yapılır.

<img width="991" height="363" alt="image" src="https://github.com/user-attachments/assets/8f903cf8-ff46-43b9-a122-a0b425963674" />

Time Server konfigürayonu için Regedit açlışır.
Hkey_LOCAL_MAchine\system\CurrentControlSet\Services\W32Time\Parameters seçilir.
Type: NTP
NTPServer: tr.pool.ntp.org seçilir.

<img width="879" height="512" alt="image" src="https://github.com/user-attachments/assets/9a578def-18cc-46f7-9312-ff228d6ce866" />

Config altında AnnonceFlags degeri 5 yapılır.

<img width="907" height="585" alt="image" src="https://github.com/user-attachments/assets/7d27c368-d67e-4295-b041-1080f8e6a59e" />

w32time servisi restart edililir.
Not: Time Server’a (tr.pool.ntp.org) erişimin sağlanması için UDP 123 nolu portun açık olması gerekmektedir.

<img width="662" height="387" alt="image" src="https://github.com/user-attachments/assets/52241d98-12a9-42bf-8393-e656667bb448" />































