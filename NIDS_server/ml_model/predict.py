import joblib
import os
from functools import lru_cache
import pandas as pd
import numpy as np

@lru_cache
def load_model():
    model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
    return joblib.load(model_path)

def predict_intrusion(data):
    model = load_model()
    try:
        df = pd.DataFrame([data])
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna()
        df = df.drop(columns=['Timestamp', 'Protocol', 'Dst IP', 'Flow ID', 'Src Port', 'Src IP', 'Label'])
        df = df.loc[:, ~df.columns.str.contains('^Unnamed')]

        try:
            final = model.predict(df)
            return final[0]
        except ValueError as e:
            print("ValueError", e)
    except Exception as e:
        print("Exception", e)