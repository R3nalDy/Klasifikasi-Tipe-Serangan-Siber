from flask import Flask, request, jsonify
import joblib
import pandas as pd
import re

app = Flask(__name__)

# Muat model dan label encoder
model = joblib.load('attack_type_classifier_rf_optimized.pkl')
label_encoder = joblib.load('label_encoder.pkl')

# Ambil preprocessor dari pipeline
preprocessor = model.named_steps['preprocessor']

# Fungsi feature engineering (sama seperti di preprocessing)
def extract_payload_features(payload):
    if not isinstance(payload, str):
        return 0, 0
    length = len(payload)
    malicious_keywords = len(re.findall(r'eval|whoami|==|wget|curl|exec|SELECT|UNION|WHERE|etc|passwd|.exe|.bin|anydesk.exe|powershell.exe|monlist|ps|FROM|bypass|dlink|mimikatz.exe', payload, re.IGNORECASE))
    return length, min(malicious_keywords, 1)


@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        df = pd.DataFrame([data])

        # Feature engineering
        df['Payload_Length'] = df['Payload Data'].apply(extract_payload_features).apply(lambda x: x[0])
        df['Payload_Malicious'] = df['Payload Data'].apply(extract_payload_features).apply(lambda x: x[1])
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        df['Hour'] = df['Timestamp'].dt.hour
        df['Has_Malware_Indicator'] = df['Malware Indicators'].apply(lambda x: 1 if x != 'None' else 0)

        # Pilih fitur yang sama seperti saat pelatihan
        final_features = ['Source Port', 'Destination Port', 'Packet Length', 'Payload_Length',
                          'Hour', 'Payload_Malicious', 'Has_Malware_Indicator', 'Protocol', 'Traffic Type']
        df = df[final_features]

        # Transformasi data menggunakan preprocessor
        processed_data = preprocessor.transform(df)

        # Prediksi
        prediction_encoded = model.named_steps['classifier'].predict(processed_data)
        prediction = label_encoder.inverse_transform(prediction_encoded)
        return jsonify({'Attack Type': prediction[0]})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


