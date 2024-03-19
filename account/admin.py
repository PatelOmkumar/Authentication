from django.contrib import admin
from account.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import Role
from .models import Permission
from .models import RolePermission,UserPermission

# Register your models here.
class RoleAdmin(admin.ModelAdmin):
    list_display = ["role_id","role_name"]

class PermissionAdmin(admin.ModelAdmin):
    list_display = ["permission_id","permission_name","permission_description"]

class RolePermissionAdmin(admin.ModelAdmin):
    list_display = ["role_id","permission_id"]

class UserPermissionAdmin(admin.ModelAdmin):
    list_display = ["id","user_id","permission_id"]

class UserModelAdmin(BaseUserAdmin):

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserModelAdmin
    # that reference specific fields on auth.User.
    list_display = ["id", "email", "name", "phone",
                    "date_of_birth", "gender", "address","role_id","password", "is_verified", "is_admin","is_superuser"]
    list_filter = ["is_admin","is_superuser","is_verified"]
    fieldsets = [
        ('User Credentials', {"fields": ["email", "password"]}),
        ("Personal info", {"fields": [
         "name", "phone", "date_of_birth", "gender", "address","role_id"]}),
        ("Permissions", {"fields": ["is_admin","is_superuser","is_verified"]}),
    ]
    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = [
        (
            None,
            {
                "classes": ["wide"],
                "fields": ["email", "name", "phone", "date_of_birth", "gender", "address", "role_id","password1", "password2"],
            },
        ),
    ]
    search_fields = ["email"]
    ordering = ["email", "id"]
    filter_horizontal = []


# Now register the new UserAdmin...
admin.site.register(User, UserModelAdmin)
admin.site.register(Role,RoleAdmin)
admin.site.register(Permission,PermissionAdmin)
admin.site.register(RolePermission,RolePermissionAdmin)
admin.site.register(UserPermission,UserPermissionAdmin)
