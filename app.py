import joblib
from pathlib import Path 
import pandas as pd
import streamlit as st

dataset = pd.read_csv(
    Path("clean_dataset.csv"), 
    skip_blank_lines=True, 
    header=0)

dataset["latency"] = pd.to_numeric(dataset.latency, errors='coerce')
dataset["hops"] = pd.to_numeric(dataset.hops, errors='coerce')
grouped = dataset.groupby(dataset.origin)
test_set = grouped.get_group("Mullvad")

ensemble = joblib.load('geolocation_pipeline.pkl')

st.title('Geolocation predicator')
st.subheader("Unfortunately, you have to input the latency and the number of hops manually. Streamlit doesn't allow socket access.")
latency = st.number_input("Latency in milliseconds", value=13)
hops = st.number_input("Number of hops", min_value=1, max_value=30, value=10)

if st.button('Run prediction'):
    input_df = pd.DataFrame([[latency, hops]], columns=['latency','hops'])

    prediction = ensemble.predict(input_df)
    st.success(f'Predicted geolocation: {prediction}')