from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, JsonResponse
from .models import IntrusionRecord
from datetime import timedelta
from ml_model.predict import predict_intrusion
import json
from collections import defaultdict
from django.db.models import Count, Case, When, IntegerField
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
    """API endpoint to fetch attack data for the chart - optimized for performance"""
    # Get records from the last 5 minutes
    end_time = timezone.now()
    start_time = end_time - timedelta(minutes=5)
    
    # Round the times to the nearest 30-second interval
    seconds = start_time.second
    microseconds = start_time.microsecond
    start_time = start_time - timedelta(seconds=seconds % 30, microseconds=microseconds)
    
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
    
    # Initialize data structure
    attack_counts = {
        'labels': [interval['label'] for interval in intervals],
        'datasets': {
            'DDoS': [0] * 10,
            'PortScan': [0] * 10,
            'Other': [0] * 10
        }
    }
    
    # Use optimized database query with single query using group by
    for i, interval in enumerate(intervals):
        # Get counts for each attack type in this interval using annotations
        counts = IntrusionRecord.objects.filter(
            detected__gte=interval['start'],
            detected__lt=interval['end']
        ).aggregate(
            ddos_count=Count(Case(
                When(attack='DDoS', then=1),
                output_field=IntegerField()
            )),
            portscan_count=Count(Case(
                When(attack='PortScan', then=1),
                output_field=IntegerField()
            )),
            other_count=Count(Case(
                When(attack__in=['DDoS', 'PortScan'], then=None),
                default=1,
                output_field=IntegerField()
            ))
        )
        
        attack_counts['datasets']['DDoS'][i] = counts['ddos_count']
        attack_counts['datasets']['PortScan'][i] = counts['portscan_count']
        attack_counts['datasets']['Other'][i] = counts['other_count']
    
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