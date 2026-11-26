import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent / "src"))
import streamlit as st
from detector import check
from features import domain_features, ssl_features

st.set_page_config(page_title="Explainable Phishing Detector", page_icon="🛡️")
st.title("Explainable Phishing Detector")
st.caption("Major project prototype: URL-based XGBoost model with SHAP-based reasons")

url = st.text_input("Enter a URL", placeholder="https://example.com/login")
extra = st.checkbox("Also show live domain-age and SSL info (use only for trusted URLs)")

if st.button("Check") and url.strip():
    r = check(url)
    color = {"HIGH": "red", "MEDIUM": "orange", "LOW": "green"}[r["level"]]
    st.markdown(f"### Risk: :{color}[{r['risk']:.0f}% ({r['level']})]")
    st.progress(min(int(r["risk"]), 100))
    st.subheader("Why?")
    if r["reasons"]:
        for t in r["reasons"]:
            st.write("- " + t)
    else:
        st.write("No strong risk signals found in the URL.")
    with st.expander("URL features used by the model"):
        st.json(r["features"])
    if extra:
        st.subheader("Extra live checks (not yet used in the score)")
        st.json({**domain_features(url), **ssl_features(url)})