from django.contrib import admin

from .models import Memo


class MemoAdmin(admin.ModelAdmin):
    list_display = ('sender', 'recipient', 'subject', 'body', 'encrypt')

admin.site.register(Memo, MemoAdmin)