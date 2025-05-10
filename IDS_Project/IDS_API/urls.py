from django.urls import path
from .views import predict_intrusion, show_data

urlpatterns = [
    path('predict/', predict_intrusion, name='predict'),
    path('show/', show_data, name='show-data')
]