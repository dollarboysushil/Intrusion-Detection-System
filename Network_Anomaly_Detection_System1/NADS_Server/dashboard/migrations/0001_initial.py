# Generated by Django 5.2.1 on 2025-06-18 03:35

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AttackLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('device_id', models.CharField(default='1', max_length=100)),
                ('host_ip', models.GenericIPAddressField()),
                ('destination_ip', models.GenericIPAddressField()),
                ('attack', models.CharField(max_length=100)),
                ('timestamp', models.DateTimeField()),
            ],
        ),
    ]
