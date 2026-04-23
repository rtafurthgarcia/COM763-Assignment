import joblib
from pathlib import Path 
import pandas as pd
import streamlit as st
import socket

from collect import run_measurement

def input_valid(dn_or_ip):
    try:
        socket.gethostbyname(dn_or_ip)
        return True
    except:
        return False

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

server = st.text_input("IP or domain name", value="wrexham.ac.uk")
port = st.number_input("Port of the server", min_value=1, max_value=65535, value=53)
max = st.number_input("Max number of measurements", min_value=1, max_value=3, value=1)
results = None
if input_valid(server):
    results = run_measurement(server, port, max)
else:
    st.error("Invalid ip address or domain name.")

if results is not None:
    latency, hops = results

    input_df = pd.DataFrame([[latency, hops]], columns=['latency','hops'])

    prediction = ensemble.predict(input_df)
    st.success(f'Predicted geolocation: {prediction}')
else:
    st.error("Couldn't run measurements.")