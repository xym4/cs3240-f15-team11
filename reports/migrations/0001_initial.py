# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Choice',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('choice_text', models.CharField(max_length=200)),
                ('votes', models.IntegerField(default=0)),
            ],
        ),
        migrations.CreateModel(
            name='Folder',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('Folder_Name', models.CharField(max_length=200)),
                ('creator', models.ForeignKey(related_name='creator', to=settings.AUTH_USER_MODEL, null=True, default=None)),
            ],
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('title', models.CharField(max_length=200)),
                ('Short_Description', models.CharField(max_length=200)),
                ('Detailed_Description', models.TextField(max_length=1000)),
                ('Location_of_Event', models.CharField(max_length=100)),
                ('Attachments', models.FileField(blank=True, upload_to='report')),
                ('Attachment_is_Encrypted', models.BooleanField(default=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('group_name', models.CharField(default='Public', max_length=200)),
                ('author', models.ForeignKey(related_name='author', to=settings.AUTH_USER_MODEL, null=True)),
                ('folder', models.ForeignKey(related_name='author', to='reports.Folder', null=True, default=None)),
            ],
        ),
        migrations.CreateModel(
            name='Sensitivity',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('sensitivity', models.IntegerField(choices=[(3, 'public'), (2, 'private')])),
            ],
        ),
        migrations.AddField(
            model_name='choice',
            name='question',
            field=models.ForeignKey(to='reports.Report'),
        ),
    ]
