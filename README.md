# Klasifikasi-Tipe-Serangan-Siber

## 📌 Deskripsi
Proyek ini membuat klasifikasi tipe serangan siber  (DDOS, Malware, Intrusion) menggunakan dataset log jaringan.

## 🛠️ Fitur Utama
- **Model**: Random Forest yang dioptimalkan dengan Grid Search.
- **Fitur Input**: Source Port, Destination Port, Packet Length, Payload Data, Timestamp, Malware Indicators, Protocol, Traffic Type.
- **Feature Engineering**: Ekstraksi panjang dan kata kunci berbahaya dari Payload Data, ekstraksi jam dari Timestamp, dan fitur biner dari Malware Indicators.
- **Endpoint API**: /predict untuk prediksi jenis serangan.


