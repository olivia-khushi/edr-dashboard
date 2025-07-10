import streamlit as st
import pandas as pd
import joblib
import shap
import matplotlib.pyplot as plt


# MITRE ATT&CK Mapping (basic example)
mitre_map = {
    0: "🟢 Normal Activity",
    1: "🛑 Analysis → Reverse Engineering",
    2: "🛑 Backdoor → Command & Control",
    3: "🛑 DoS → Resource Exhaustion",
    4: "🛑 Exploits → Privilege Escalation",
    5: "🛑 Fuzzers → Vulnerability Discovery",
    6: "🛑 Generic → Unknown Signature",
    7: "🛑 Reconnaissance → Info Collection",
    8: "🛑 Shellcode → Remote Execution",
    9: "🛑 Worms → Lateral Movement",
    10: "⚠️ Unclassified or No Attack Info"
}




# Load the model
model = joblib.load("model.pkl")

# Upload CSV feature
st.sidebar.header("📁 Upload Your CSV File")
uploaded_file = st.sidebar.file_uploader("Choose a CSV file", type=["csv"])

if uploaded_file is not None:
    data = pd.read_csv(uploaded_file)
    st.success("✅ File uploaded successfully!")
else:
    st.warning("⚠️ Using default sample data.")
    data = pd.read_csv("test_data.csv")

st.set_page_config(page_title="EDR Dashboard", layout="wide")

st.title("🚨 Endpoint Detection & Response (EDR) Dashboard")
st.markdown("Built with ❤️ by a 4th-year engineering student")

st.subheader("🔍 Sample Network Events")
st.dataframe(data.head(10))

# Predict button
if st.button("Detect Anomalies"):
    predictions = model.predict(data)
    data['Prediction'] = predictions
    data['MITRE_Tag'] = data['Prediction'].map(mitre_map)

    st.write("🧪 Starting SHAP...")

    # Drop MITRE_Tag and Prediction before passing to SHAP
    features = data.drop(columns=["Prediction", "MITRE_Tag"], errors="ignore")

    # Convert only numerical features
    features_numeric = features.select_dtypes(include=["int64", "float64", "bool"])

    explainer = shap.Explainer(model)
    shap_values = explainer(features_numeric)

    st.write("✅ SHAP finished computing")
    

    st.subheader("🧠 Global Explainability (All Predictions)")
    fig1, ax1 = plt.subplots(figsize=(10, 5))
    shap.plots.bar(shap_values, max_display=10, show=False)
    st.pyplot(fig1)


    st.success("✅ Prediction complete!")
    
    st.subheader("🛡️ Detection Results")
    st.write(data[['Prediction']].value_counts())
    
    st.subheader("📊 MITRE Attack Summary")
    mitre_summary = data['MITRE_Tag'].value_counts()
    st.bar_chart(mitre_summary)


    st.dataframe(data[['Prediction', 'MITRE_Tag']].head(10))




