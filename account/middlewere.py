from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist
from account.models import Permission, RolePermission, User, UserPermission


class ExampleMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request, view_name=None):
        user_id = request.user.id
        print(user_id)

        if request.path.startswith('/admin/'):
            return self.get_response(request)

        try:
            user = User.objects.get(id=user_id)
        except ObjectDoesNotExist:
            return JsonResponse({"error": "User not found. Please check your credentials."}, status=404)

        role_permissions = RolePermission.objects.filter(role_id=user.role_id)
        user_permissions = UserPermission.objects.filter(user_id=user_id)

        if not role_permissions.exists():
            return JsonResponse({"error": "No role permissions found for this role."}, status=403)
        if not user_permissions.exists():
            return JsonResponse({"error": "No user permissions found for this role."}, status=403)

        role_permission_ids = [rp.id for rp in role_permissions]
        user_permission_ids = [up.id for up in user_permissions]

        get_role_permissions = Permission.objects.filter(
            rolepermission__in=role_permission_ids)

        get_user_permissions = Permission.objects.filter(
            userpermission__in=user_permission_ids)

        if not get_role_permissions.exists():
            return JsonResponse({"error": "No get_role_permissions found for this role."}, status=403)
        if not get_user_permissions.exists():
            return JsonResponse({"error": "No get_user_permissions found for this role."},
                                status=403)

        role_permission_names = [
            p.permission_name for p in get_role_permissions]
        user_permission_names = [
            p.permission_name for p in get_user_permissions]

        print("view anme = ", view_name)
        print("ROle Permissions is = ", role_permission_names)
        print("User permissions is = ", user_permission_names)

        if view_name:
            if view_name in role_permission_names and view_name in user_permission_names:
                return JsonResponse({"ok": f"You have permission to access {view_name}."}, status=200)
            else:
                return JsonResponse({"error": f"You do not have permission to access {view_name}."}, status=403)

        return self.get_response(request)


# class ExampleMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request, view_name=None):
#         user_id = request.user.id
#         print(user_id)

#         if request.path.startswith('/admin/'):
#             return self.get_response(request)

#         try:
#             user = User.objects.get(id=user_id)
#         except ObjectDoesNotExist:
#             return JsonResponse({"error": "User not found. Please check your credentials."}, status=404)

#         role_permissions = RolePermission.objects.filter(role_id=user.role_id)
#         user_permissions = UserPermission.objects.filter(user_id=user_id)
#         print(user_permissions)

#         if not role_permissions.exists() or not user_permissions.exists():
#             return JsonResponse({"error": "No role or user permissions found for this role."}, status=403)
#         # if not user_permissions.exists():
#         #     return JsonResponse({"error": "No user permissions found for this role."}, status=403)

#         role_permission_ids = [rp.id for rp in role_permissions]
#         user_permission_ids = [up.id for up in user_permissions]

#         get_role_permissions = Permission.objects.filter(
#             rolepermission__in=role_permission_ids)

#         get_user_permissions = Permission.objects.filter(
#             userpermission__in=user_permission_ids)

#         if not get_role_permissions.exists() or not get_user_permissions.exists():
#             return JsonResponse({"error": "No get_role_permissions or get_user_permissions  found for this role."}, status=403)
#         # if not get_user_permissions.exists():
#         #     return JsonResponse({"error": "No get_user_permissions found for this role."}, status=403)

#         role_permission_names = [
#             p.permission_name for p in get_role_permissions]
#         user_permission_names = [
#             p.permission_name for p in get_user_permissions]

#         print(view_name)
#         print(role_permission_names)
#         print(user_permission_names)

#         if view_name:
#             if view_name not in role_permission_names or view_name not in user_permission_names:
#                  return JsonResponse({"error": f"You do not have permission to access {view_name}."}, status=403)
#         else:
#              return JsonResponse({"ok": f"You have permission to access {view_name}."}, status=200)
        # if view_name:
        #     if view_name in role_permission_names or user_permission_names:
        #         print(role_permission_names)
        #         print(user_permission_names)
        #         print(view_name)
        #         return JsonResponse({"ok": f"You  have permission to access {view_name}."}, status=200)
        # else:
        #      return JsonResponse({"error": f"You do not have permission to access {view_name}."}, status=403)


#         return self.get_response(request)
