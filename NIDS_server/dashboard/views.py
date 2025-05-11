from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, JsonResponse
from .models import IntrusionRecord
from datetime import timedelta
from ml_model.predict import predict_intrusion
import json
from collections import defaultdict

# Create your views here.

def dashboard(request):
    return render(request, 'dashboard.html')

@csrf_exempt
def predict_view(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            prediction = predict_intrusion(data)
            IntrusionRecord.objects.create(
                attack = prediction
            )
            print(prediction)
        except ValueError as e:
            print("ValueError:", e)
        return HttpResponse(status=204)  # No Content
    return HttpResponse(status=405)




def attack_dashboard(request):
    """Render the dashboard page with the chart"""
    return render(request, 'attack_dashboard.html')

def get_attack_data(request):
    """API endpoint to fetch attack data for the chart"""
    # Get records from the last 5 minutes
    end_time = timezone.now()
    start_time = end_time - timedelta(minutes=5)
    
    # Round the times to the nearest 30-second interval to create stable time buckets
    # This ensures consistency between refreshes
    seconds = start_time.second
    microseconds = start_time.microsecond
    # Round down to the nearest 30-second mark
    start_time = start_time - timedelta(seconds=seconds % 30, microseconds=microseconds)
    
    # Query all records in the time range
    records = IntrusionRecord.objects.filter(
        detected__gte=start_time,
        detected__lte=end_time
    ).order_by('detected')
    
    # Define the interval (30 seconds)
    interval = timedelta(seconds=30)
    
    # Create fixed time intervals
    intervals = []
    current_interval = start_time
    
    # Create exactly 10 intervals (5 minutes ÷ 30 seconds = 10 intervals)
    for _ in range(10):
        intervals.append({
            'start': current_interval,
            'end': current_interval + interval,
            'label': current_interval.strftime('%H:%M:%S')
        })
        current_interval += interval
    
    # Initialize the data structure for counting attacks
    attack_counts = {
        'labels': [],
        'datasets': {
            'DDoS': [],
            'PortScan': [],
            'Other': []  # For all other attack types
        }
    }
    
    # Pre-calculate counts for all intervals
    interval_counts = {}
    for interval in intervals:
        # Count records in this interval
        interval_records = records.filter(
            detected__gte=interval['start'],
            detected__lt=interval['end']
        )
        
        # Count by attack type
        counts = {'DDoS': 0, 'PortScan': 0, 'Other': 0}
        for record in interval_records:
            if record.attack == 'DDoS':
                counts['DDoS'] += 1
            elif record.attack == 'PortScan':
                counts['PortScan'] += 1
            else:
                counts['Other'] += 1
                
        interval_counts[interval['label']] = counts
    
    # Populate the data structure in order
    for interval in intervals:
        label = interval['label']
        attack_counts['labels'].append(label)
        counts = interval_counts[label]
        
        attack_counts['datasets']['DDoS'].append(counts['DDoS'])
        attack_counts['datasets']['PortScan'].append(counts['PortScan'])
        attack_counts['datasets']['Other'].append(counts['Other'])
    
    # Format for Chart.js
    chart_data = {
        'labels': attack_counts['labels'],
        'datasets': [
            {
                'label': 'DDoS',
                'data': attack_counts['datasets']['DDoS'],
                'borderColor': 'rgb(255, 99, 132)',
                'backgroundColor': 'rgba(255, 99, 132, 0.1)',
                'tension': 0.3,
                'fill': False
            },
            {
                'label': 'Port Scan',
                'data': attack_counts['datasets']['PortScan'],
                'borderColor': 'rgb(255, 159, 64)',
                'backgroundColor': 'rgba(255, 159, 64, 0.1)',
                'tension': 0.3,
                'fill': False
            },
            {
                'label': 'Other Attack',
                'data': attack_counts['datasets']['Other'],
                'borderColor': 'rgb(153, 102, 255)',
                'backgroundColor': 'rgba(153, 102, 255, 0.1)',
                'tension': 0.3,
                'fill': False
            }
        ]
    }
    
    return JsonResponse(chart_data)