import streamlit as st
import pandas as pd
import joblib
import shap
import matplotlib.pyplot as plt

# Configure the Streamlit page
st.set_page_config(page_title="EDR Threat Detection Dashboard", layout="wide")
st.title("🚨 Endpoint Detection & Response (EDR) Dashboard")
st.markdown("🔐 Built by Anushka Roy | DRDO Internship Project")
st.markdown("---")

# Load trained model
@st.cache_resource
def load_model():
    return joblib.load("model.pkl")

model = load_model()

# MITRE ATT&CK Mapping
mitre_map = {
    0: "🟢 Normal Activity",
    1: "🛑 T1063 → Security Software Discovery (Analysis)",
    2: "🛑 T1071.001 → Application Layer Protocol (Backdoor C2)",
    3: "🛑 T1499 → Resource Exhaustion (DoS)",
    4: "🛑 T1068 → Exploitation for Privilege Escalation",
    5: "🛑 T1595 → Active Scanning (Fuzzers)",
    6: "🛑 T1204.002 → User Execution via Malicious File (Generic)",
    7: "🛑 T1592 → Gather Victim Host Information (Recon)",
    8: "🛑 T1059.001 → Command-Line Interface (Shellcode)",
    9: "🛑 T1105 → Ingress Tool Transfer (Worms)",
    10: "⚠️ T9999 → Unknown Signature / Needs Review"
}


# Upload feature
st.sidebar.header("📁 Upload Your CSV File")
uploaded_file = st.sidebar.file_uploader("Choose a test CSV file", type=["csv"])
# SIEM Simulation Mode
st.sidebar.markdown("---")
st.sidebar.header("🔌 SIEM Simulation")
live_mode = st.sidebar.toggle("Activate Live Log Feed Simulation", value=False)


if uploaded_file is not None:
    data = pd.read_csv(uploaded_file)
    st.sidebar.success("✅ File uploaded successfully!")
else:
    st.sidebar.warning("⚠️ No file uploaded. Using sample test_data.csv")
    data = pd.read_csv("test_data.csv")

st.subheader("📝 Simulated Real-Time Network Stream")
row_slider = st.slider("🕓 Number of recent events to show", 1, len(data), 10)
st.dataframe(data.tail(row_slider), use_container_width=True)

# Predict button
# Trigger detection manually or via live mode
if st.button("🚀 Detect Anomalies") or live_mode:
    with st.spinner("Detecting anomalies in real-time..."):
        # Run predictions
        predictions = model.predict(data)
        data["Prediction"] = predictions
        data["MITRE_Tag"] = data["Prediction"].map(mitre_map)

        # Drop added columns before SHAP
        features = data.drop(columns=["Prediction", "MITRE_Tag"], errors="ignore")
        features_numeric = features.select_dtypes(include=["int64", "float64", "bool"])

        # Use SHAP TreeExplainer for XGBoost
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(features_numeric)

    st.success("✅ Anomaly Detection Complete!")

    # Summary of predictions
    st.subheader("🧮 Prediction Summary")
    summary_counts = data["Prediction"].value_counts().rename(index=mitre_map)
    st.bar_chart(summary_counts)

    # MITRE bar chart
    st.subheader("📊 MITRE ATT&CK Summary")
    mitre_summary = data["MITRE_Tag"].value_counts()
    st.bar_chart(mitre_summary)

    # Display sample results
    st.subheader("🔍 Detailed Detection Results")
    st.dataframe(data[["Prediction", "MITRE_Tag"]].head(10))

    # SHAP explainability
    st.subheader("🧠 SHAP Global Feature Importance")
    st.caption("Top 10 features influencing model predictions")
    fig, ax = plt.subplots(figsize=(10, 5))
    shap.summary_plot(shap_values, features_numeric, plot_type="bar", max_display=10, show=False)
    st.pyplot(fig)
