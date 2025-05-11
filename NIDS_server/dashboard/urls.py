from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('predict/', views.predict_view, name='predict_view'),
    
    
    path('dashboard/', views.attack_dashboard, name='attack_dashboard'),
    path('api/attack-data/', views.get_attack_data, name='get_attack_data'),
]