import os
import joblib
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
import json
import pandas as pd
import numpy as np
from .models import Attacks
from django.http import HttpResponse

# Load the model once when the server starts
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ml_model', 'model.pkl')
model = joblib.load(MODEL_PATH)

@csrf_exempt
def predict_intrusion(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            df = pd.DataFrame([data])
            df = df.replace([np.inf, -np.inf], np.nan)
            df = df.dropna()
            df = df.drop(columns=['Timestamp', 'Protocol', 'Dst IP', 'Flow ID', 'Src Port', 'Src IP', 'Label'])
            df = df.loc[:, ~df.columns.str.contains('^Unnamed')]
            try:
                final = model.predict(df)
                Attacks.objects.create(
                name = final
            )
                print(final)
            except ValueError as e:
                print("ValueError:", e)
            return JsonResponse({"prediction": final[0]})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Only POST allowed"}, status=405)

def show_data(request):
    attacks = Attacks.objects.all()
    data = []

    for attack in attacks:
        local_time = timezone.localtime(attack.created)
        data.append({
            'name': attack.name,
            'created_at': local_time.strftime('%Y-%m-%d %H:%M:%S')
        })

    return JsonResponse({'data': data})

