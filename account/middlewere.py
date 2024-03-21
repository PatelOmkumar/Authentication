from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import get_object_or_404
from account.models import Permission, Role, RolePermission, User, UserPermission
from rest_framework.request import Request
from rest_framework.response import Response
from django.urls import resolve


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


class ExampleMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request,view_name=None):
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
        # print(user_permissions)


        if not role_permissions.exists():
            return JsonResponse({"error": "No role permissions found for this role."}, status=403)
        if not user_permissions.exists():
            return JsonResponse({"error": "No user permissions found for this role."}, status=403)

        role_permission_ids = [rp.id for rp in role_permissions]
        user_permission_ids = [up.id for up in user_permissions]

        get_role_permissions = Permission.objects.filter(
            rolepermission__in=role_permission_ids)

        get_user_permissions = Permission.objects.filter(userpermission__in = user_permission_ids)

        if not get_role_permissions.exists():
            return JsonResponse({"error": "No get_role_permissions found for this role."}, status=403)
        if not get_user_permissions.exists():
            return JsonResponse({"error": "No get_user_permissions found for this role."}, 
       status=403)

        role_permission_names = [p.permission_name for p in get_role_permissions]
        user_permission_names = [p.permission_name for p in get_user_permissions]
        # print(role_permission_names)

        print(view_name)
        print(role_permission_names)
        print(user_permission_names)

        # if view_name:
        #     if view_name not in role_permission_names and user_permission_names:
        #         return JsonResponse({"error": f"You do not have permission to access {view_name}."}, status=403)
        #     else:
        #         return JsonResponse({"ok": f"You  have permission to access {view_name}."}, status=200)
        print(view_name) 
        if view_name:
            if view_name in role_permission_names and view_name in user_permission_names:
                print(view_name)
                print(role_permission_names)
                print(user_permission_names)
                return JsonResponse({"ok": f"You have permission to access {view_name}."}, status=200)
            else:
                # return True
                print("not")
                return JsonResponse({"error": f"You do not have permission to access {view_name}."}, status=403)
        
        return self.get_response(request)
    
        # if view_name:
        #     if view_name not in role_permission_names:
        #         return JsonResponse({"error": f"You do not have permission to access {view_name}."}, status=403)
        #     else:
        #         return JsonResponse({"ok": f"You  have permission to access {view_name}."}, status=200)

        # return self.get_response(request)




# class ExampleMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response
#         print("first")

#     # def __call__(self, request, *args, **kwargs):
#     def __call__(self, request:Request, *args, **kwargs):
#         print("body")
#         # if not request.user.is_authenticated:
#         user_id = request.user.id
#             # return JsonResponse({"detail": "AAAAAuthentication credentials were not provided."}, status=401)

#         # user_id = request._request.user.id
#         print(user_id)

#         if request.path.startswith('/admin/'):
#             return self.get_response(request)
#         try:
#             user = User.objects.get(id=user_id)
#             print(user)

#         except ObjectDoesNotExist:
#             return JsonResponse({"error": "User not found. Please check your credentials."}, status=404)

#         role_permissions = RolePermission.objects.filter(role_id=user.role_id)
#         # print(role_permissions)

#         if not role_permissions.exists():
#             return JsonResponse({"error": "No role permissions found for this role."}, status=403)


#         # role_permission_ids = [rp.id for rp in role_permissions]
#         role_permission_ids = [rp.id for rp in role_permissions]
#         # permissions = Permission.objects.filter(rolepermission__in=role_permission_ids)
#         permissions = Permission.objects.filter(rolepermission__in=role_permission_ids)
#         print(role_permission_ids)
#         print(permissions)
#         if not permissions:
#             return JsonResponse({"error": "No permissions found for this role."}, status=403)

#         print("found permission")
#         permission_names = [p.permission_name for p in permissions]

#         for permission in permissions:
#             # if permission.permission_name in permission_names:
#             #     print("User has permission:", permission.permission_name)
#                if permission.permission_name in permission_names:
#                    return True


#         response = self.get_response(request)
#         # response = True
#         return response


# from django.http import JsonResponse
# from account.models import Permission, RolePermission, User


# class ExampleMiddleware:
#     def __init__(self, get_response=None):
#         self.get_response = get_response
#         print("first")

#     def __call__(self, request, *args, **kwargs):
#         print("body")
#         user_id = request.user.id
#         print(user_id)

#         user = User.objects.get(id=user_id)
#         print(user)

#         if not user:
#             return JsonResponse({"error": "User not found. Please check your credentials."}, status=404)

#         role_permissions = RolePermission.objects.filter(role_id=user.role_id)
#         # print(role_permissions)

#         if not role_permissions:
#             return JsonResponse({"error": "No permissions found for this role."}, status=403)
#         print("have   print(role_permissions)")

#         # Extract permission IDs from the permission objects
#         # permission_ids = [rp.permission_id for rp in role_permissions]
#         role_permission_ids = [rp.id for rp in role_permissions]
#         permissions = Permission.objects.filter(rolepermission__in=role_permission_ids)

#         if not permissions:
#             return JsonResponse({"error": "No permissions found for this role."}, status=403)
#         print("found permission")
#         # Extract permission names
#         permission_names = [p.permission_name for p in permissions]
#         for permission in permissions:
#             if permission.permission_name in permission_names:
#                 print("User has permission:")
#                 response = self.get_response(request)
#                 return response

#         return JsonResponse({"error": "Access denied. You do not have permission to access this resource."}, status=403)


# from django.http import JsonResponse
# from django.core.exceptions import ObjectDoesNotExist
# from account.models import Permission, RolePermission, User


# class ExampleMiddleware:
#     def __init__(self, get_response=None):
#         self.get_response = get_response
#         print("first")

#     def __call__(self, request, *args, **kwargs):
#         print("body")
#         user_id = request.user.id
#         print(user_id)

#         if request.path.startswith('/admin/'):
#             return self.get_response(request)
#         try:
#             user = User.objects.get(id=user_id)
#             print(user)

#         except ObjectDoesNotExist:
#             return JsonResponse({"error": "User not found. Please check your credentials."}, status=404)

#         role_permissions = RolePermission.objects.filter(role_id=user.role_id)
#         print("have   print(role_permissions)")

#         if not role_permissions:
#             return JsonResponse({"error": "No permissions found for this role."}, status=403)

#         role_permission_ids = [rp.id for rp in role_permissions]
#         permissions = Permission.objects.filter(
#             rolepermission__in=role_permission_ids)

#         if not permissions:
#             return JsonResponse({"error": "No permissions found for this role."}, status=403)

#         print("found permission")
#         permission_names = [p.permission_name for p in permissions]

#         for permission in permissions:
#             if permission.permission_name in permission_names:
#                 print("User has permission:", permission.permission_name)

#         response = self.get_response(request)
#         print("last")
#         return response
