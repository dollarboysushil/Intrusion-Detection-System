from django.db import models

# Create your models here.

class IntrusionRecord(models.Model):
    attack = models.CharField(max_length=100)
    detected = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.attack} at {self.detected}"