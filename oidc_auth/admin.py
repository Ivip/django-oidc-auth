from django.contrib import admin

from .models import OpenIDProvider


class OpenIDProviderAdmin(admin.ModelAdmin):
    list_display = ('issuer', 'client_id')
    list_filter = ('signing_alg',)


admin.site.register(OpenIDProvider, OpenIDProviderAdmin)
