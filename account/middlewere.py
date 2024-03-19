from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist
from account.models import Permission, RolePermission, User


class ExampleMiddleware:
    def __init__(self, get_response=None):
        self.get_response = get_response
        print("first")

    def __call__(self, request, *args, **kwargs):
        print("body")
        user_id = request.user.id
        print(user_id)

        if request.path.startswith('/admin/'):
            return self.get_response(request)
        try:
            user = User.objects.get(id=user_id)
            print(user)

        except ObjectDoesNotExist:
            return JsonResponse({"error": "User not found. Please check your credentials."}, status=404)

        role_permissions = RolePermission.objects.filter(role_id=user.role_id)
        print("have   print(role_permissions)")

        if not role_permissions:
            return JsonResponse({"error": "No permissions found for this role."}, status=403)

        role_permission_ids = [rp.id for rp in role_permissions]
        permissions = Permission.objects.filter(
            rolepermission__in=role_permission_ids)

        if not permissions:
            return JsonResponse({"error": "No permissions found for this role."}, status=403)

        print("found permission")
        permission_names = [p.permission_name for p in permissions]

        for permission in permissions:
            if permission.permission_name in permission_names:
                print("User has permission:", permission.permission_name)

        response = self.get_response(request)
        print("last")
        return response


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
# from django.contrib.auth.models import Permission
# from .models import User, Role, RolePermission


# class PermissionMiddleware:
#     def __init__(self, get_response=None):
#         self.get_response = get_response

#     def __call__(self, request):
    #         user_id = request.user.id
    #         print(user_id)

#         try:
#             # Find the user by primary key
#             user = User.objects.get(id=user_id)
#             print(user)

#             if request.path.startswith('/admin/'):
#                 return self.get_response(request)

#             if not user:
#                 print("user found")
#                 return JsonResponse({"error": "User not found. Please check your credentials."}, status=404)


#             # Get the role permissions associated with the user's role
#             role_permissions = RolePermission.objects.filter(
#                 role_id=user.role_id)
#             print(role_permissions)

#             if not role_permissions:
#                 print("have   print(role_permissions)")
#                 return JsonResponse({"error": "No permissions found for this role."}, status=403)

#             # Extract permission IDs
#             permission_ids = [rp.permission_id for rp in role_permissions]

#             # Get the permission objects
#             permissions = Permission.objects.filter(id__in=permission_ids)

#             if not permissions:
#                 return JsonResponse({"error": "No permissions found for this role."}, status=403)

#             # Extract permission names
#             permission_names = [p.permission_name for p in permissions]

#             if permissions in permission_names:
#                 print("User has permission:", permissions)
#                 return self.get_response(request)

#             return JsonResponse({"error": "Access denied. You do not have permission to access this resource."}, status=403)

#         except User.DoesNotExist:
#             return JsonResponse({"error": "User not found. Please check your credentials."}, status=404)

#         except Exception as e:
#             print("Error occurred:", e)
#             return JsonResponse({"error": "Oops! Something went wrong. Please try again later."}, status=500)


# from pydoc import resolve
# from django.http import JsonResponse
# from django.contrib.auth import get_user_model
# from django.shortcuts import get_object_or_404
# from django.urls import Resolver404

# from .models import RolePermission

# User = get_user_model()

# class RolePermissionMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         if request.user.is_authenticated:
#             # Skip permission check for requests to the Django admin interface
#             if request.path.startswith('/admin/'):
#                 return self.get_response(request)

#             # Get the user's role
#             user_role = request.user.role_id

#             try:
#                 # Get the resolved view name from the request path
#                 resolved_view_name = resolve(request.path_info).view_name
#             except Resolver404:
#                 resolved_view_name = None

#             # Check if the resolved view name requires permission
#             required_permission = self.get_required_permission(resolved_view_name)
#             if required_permission:
#                 # Check if the user's role has the required permission
#                 has_permission = self.check_permission(user_role, required_permission)

#                 if not has_permission:
#                     return JsonResponse({'error': 'You do not have permission to access this resource.'}, status=403)

#         response = self.get_response(request)
#         return response

#     def check_permission(self, role, permission):
#         # Check if the given role has the specified permission
#         return RolePermission.objects.filter(role_id=role, permission_id__permission_name=permission).exists()


# from django.http import JsonResponse
# from django.contrib.auth.models import Permission
# from .models import User, Role, RolePermission


# class IsAuthorizedMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         user_id = request.user.id

#         try:
#             # Find the user by primary key
#             user = User.objects.get(id=user_id)

#             if request.path.startswith('/admin/'):
#                 return self.get_response(request)

#             if not user:
#                 return JsonResponse({"error": "User not found. Please check your credentials."}, status=404)

#             # Get the role permissions associated with the user's role
#             role_permissions = RolePermission.objects.filter(
#                 role_id=user.role_id)

#             if not role_permissions:
#                 return JsonResponse({"error": "No permissions found for this role."}, status=403)

#             # Extract permission IDs
#             permission_ids = [rp.permission_id for rp in role_permissions]

#             # Get the permission objects
#             permissions = Permission.objects.filter(id__in=permission_ids)

#             if not permissions:
#                 return JsonResponse({"error": "No permissions found for this role."}, status=403)

#             # Extract permission names
#             permission_names = [p.permission_name for p in permissions]

#             if permissions in permission_names:
#                 print("User has permission:", permissions)
#                 return self.get_response(request)

#             return JsonResponse({"error": "Access denied. You do not have permission to access this resource."}, status=403)

#         except User.DoesNotExist:
#             return JsonResponse({"error": "User not found. Please check your credentials."}, status=404)

#         except Exception as e:
#             print("Error occurred:", e)
#             return JsonResponse({"error": "Oops! Something went wrong. Please try again later."}, status=500)


# from rest_framework import status
# from rest_framework.response import Response
# from django.contrib.auth.models import AnonymousUser
# from django.utils.deprecation import MiddlewareMixin


# class PermissionMiddleware(MiddlewareMixin):
#     def process_request(self, request):
#         user = getattr(request, 'user', None)

#         if isinstance(user, AnonymousUser):
#             return Response({"detail": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)

#         if not user.is_authenticated:
#             return Response({"detail": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)

#         required_permissions = self.get_required_permissions(request, user)

#         if not user.has_perms(required_permissions, obj=request):
#             return Response({"detail": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)

#         return None

#     def get_required_permissions(self, request, user):
#         roles = user.role_id.all()
#         permissions = []

#         for role in roles:
#             role_permissions = role.rolepermission_set.all()
#             for role_permission in role_permissions:
#                 permissions.append(role_permission.permission_id.permission_name)

#         return permissions

# from rest_framework import status
# from rest_framework.response import Response
# from django.contrib.auth.models import AnonymousUser
# from django.utils.deprecation import MiddlewareMixin

# from account.models import Permission, Role, RolePermission

# class PermissionMiddleware(MiddlewareMixin):
#     def process_request(self, request):
#         if not request.user or isinstance(request.user, AnonymousUser):
#             return Response({'error': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)

#         # Extract required role and permission based on the requested endpoint
#         required_role = self.get_required_role(request)
#         required_permission = self.get_required_permission(request)

#         # Check if the user has the required role and permission for the endpoint
#         if not self.has_permission(request, required_role, required_permission):
#             return Response({'error': 'You do not have permission to access this resource.'}, status=status.HTTP_403_FORBIDDEN)

#     def has_permission(self, request, required_role, required_permission):
#         user_roles = request.user.role_id.all()
#         user_permissions = request.user.userpermission_set.all()

#         # Check if the user has the required role
#         if required_role and required_role not in user_roles:
#             return None

#         # Check if the user has the required permission
#         if required_permission and required_permission not in user_permissions:
#             return None

#         # Check if the user's role has the required permission
#         if required_permission and required_role:
#             if not RolePermission.objects.filter(role_id=required_role, permission_id=required_permission).exists():
#                 return None

#         return True

#     def get_required_role(self, request):
#         # Logic to extract required role based on the requested endpoint
#         # Example: You can extract it from the URL or request method
#         # Return the required role object or None if no specific role is required

#         # For example, if the URL contains a parameter indicating the role
#         # You can extract it like this:
#         role_id = request.GET.get('role_id')
#         if role_id:
#             try:
#                 return Role.objects.get(id=role_id)
#             except Role.DoesNotExist:
#                 pass  # Handle the case when the role does not exist

#         # If no specific role is required, return None
#         return None

#     def get_required_permission(self, request):
#         # Logic to extract required permission based on the requested endpoint
#         # Example: You can extract it from the URL or request method
#         # Return the required permission object or None if no specific permission is required

#         # For example, if the URL contains a parameter indicating the permission
#         # You can extract it like this:
#         permission_id = request.GET.get('permission_id')
#         if permission_id:
#             try:
#                 return Permission.objects.get(id=permission_id)
#             except Permission.DoesNotExist:
#                 pass  # Handle the case when the permission does not exist

#         # If no specific permission is required, return None
#         return None

#     # def get_required_role(self, request):
#     #     # Logic to extract required role based on the requested endpoint
#     #     # Example: You can extract it from the URL or request method
#     #     # Return the required role object or None if no specific role is required
#     #     return required_role

#     # def get_required_permission(self, request):
#     #     # Logic to extract required permission based on the requested endpoint
#     #     # Example: You can extract it from the URL or request method
#     #     # Return the required permission object or None if no specific permission is required
#     #     return required_permission


# from rest_framework import status
# from django.contrib.auth.models import AnonymousUser
# from django.utils.deprecation import MiddlewareMixin
# from account.models import Permission, Role, RolePermission

# class PermissionMiddleware(MiddlewareMixin):
#     def __init__(self, get_response=None):
#         super().__init__(get_response)
#         # Initialize any other attributes or configurations here if needed

#     def process_request(self, request):
#         if not request.user or isinstance(request.user, AnonymousUser):
#             return None  # Continue processing the request

#         # Extract required role and permission based on the requested endpoint
#         required_role = self.get_required_role(request)
#         required_permission = self.get_required_permission(request)

#         # Check if the user has the required role and permission for the endpoint
#         if not self.has_permission(request, required_role, required_permission):
#             # You can perform additional actions here if needed
#             # For example, log the unauthorized access attempt
#             # or redirect the user to a different page
#             return None  # Continue processing the request

#     def has_permission(self, request, required_role, required_permission):
#         user_roles = request.user.role_id.all()
#         user_permissions = request.user.userpermission_set.all()

#         # Check if the user has the required role
#         if required_role and required_role not in user_roles:
#             return False

#         # Check if the user has the required permission
#         if required_permission and required_permission not in user_permissions:
#             return False

#         # Check if the user's role has the required permission
#         if required_permission and required_role:
#             if not RolePermission.objects.filter(role_id=required_role, permission_id=required_permission).exists():
#                 return False

#         return True

#     def get_required_role(self, request):
#         # Logic to extract required role based on the requested endpoint
#         # Example: You can extract it from the URL or request method
#         # Return the required role object or None if no specific role is required

#         # For example, if the URL contains a parameter indicating the role
#         # You can extract it like this:
#         role_id = request.GET.get('role_id')
#         if role_id:
#             try:
#                 return Role.objects.get(id=role_id)
#             except Role.DoesNotExist:
#                 pass  # Handle the case when the role does not exist

#         # If no specific role is required, return None
#         return None

#     def get_required_permission(self, request):
#         # Logic to extract required permission based on the requested endpoint
#         # Example: You can extract it from the URL or request method
#         # Return the required permission object or None if no specific permission is required

#         # For example, if the URL contains a parameter indicating the permission
#         # You can extract it like this:
#         permission_id = request.GET.get('permission_id')
#         if permission_id:
#             try:
#                 return Permission.objects.get(id=permission_id)
#             except Permission.DoesNotExist:
#                 pass  # Handle the case when the permission does not exist

#         # If no specific permission is required, return None
#         return None
