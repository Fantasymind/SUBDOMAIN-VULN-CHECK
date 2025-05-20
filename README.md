 ✨  

---

# 🕵️‍♂️ Subdomain Takeover Detector  

![banner](https://user-images.githubusercontent.com/0000000/example.png)  

## 🚀 Overview  

Subdomain Takeover Detector adalah alat berbasis Python yang memungkinkan kamu mendeteksi subdomain yang rentan terhadap **pengambilalihan (takeover)** dengan menganalisis konfigurasi DNS dan respons HTTP/S dari subdomain target.  

## 🎯 Fitur  

✅ **Deteksi CNAME yang tidak dapat diselesaikan**  
✅ **Pemeriksaan HTTP dan HTTPS**  
✅ **Identifikasi tanda-tanda takeover dengan signature detection**  
✅ **Validasi sertifikat SSL/TLS**  
✅ **Penyimpanan hasil dalam format CSV**  

## 🛠 Instalasi  

Pastikan kamu telah menginstal **Python 3.x**, lalu jalankan:  

```sh
pip install -r requirements.txt
```

## ⚙️ Konfigurasi  

Buat file `config.yaml` dengan isi berikut:  

```yaml
takeover_signatures:
  - "This domain is available"
  - "The requested URL was not found"
default_dns_servers:
  - "8.8.8.8"
  - "1.1.1.1"
```

Siapkan daftar subdomain dalam `subdomains.txt`:  

```
example.com
sub.example.com
test.example.com
```

## 🚀 Penggunaan  

Jalankan skrip dengan perintah berikut:  

```sh
python script.py -i subdomains.txt -o results.csv
```

## 📊 Output  

Hasil analisis akan tersimpan dalam `results.csv`, berisi:  

- **Subdomain**  
- **CNAME** (jika ada)  
- **Status HTTP & HTTPS**  
- **Indikasi kemungkinan takeover**  
- **Catatan tambahan**  

## 👨‍💻 Kontribusi  

Ingin berkontribusi? Fork repository ini dan buat Pull Request! 🚀  

## 📜 Lisensi  

Proyek ini menggunakan lisensi **MIT License**.  

---

✨ Semoga skrip ini membantu dalam mengamankan aset digital kamu! 🚀  
Kalau ada hal lain yang perlu diperbaiki atau ditambahkan, beri tahu saya! 🤖✨  
