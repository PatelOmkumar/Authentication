from django.http import HttpRequest, HttpResponse, JsonResponse
from rest_framework import generics
from types import GenericAlias
from django.urls import reverse_lazy
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import UserRegrstrationSerializer, UserLoginSerializer, UserDataViewSerializer, UserChangePasswordSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer, UserUpdateDetailsSerializer, AllUserDataViewSerializer
from account.middlewere import ExampleMiddleware
from .serializers import RoleSerializer, PermissionSerializer, RolePermissionSerializer, UserPermissionSerilizer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import permissions
from account.models import User
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str
from django.utils.encoding import force_str
from django.contrib.auth.tokens import default_token_generator
from .models import Role
from .models import Permission, RolePermission, UserPermission
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

# generate token manually


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class RoleListCreateView(generics.ListCreateAPIView):

    
    permission_classes = [permissions.IsAuthenticated]

   

    queryset = Role.objects.all()
    serializer_class = RoleSerializer


class RoleRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):

    # authentication_classes  = [PermissionMiddleware]
    # is_authorized_middleware = PermissionMiddleware()

    # def get(self, request, *args, **kwargs):
    #     # Check if the user is authorized
    #     if not self.is_authorized_middleware.has_permission(request):
    #         # Return an error response if the user is not authorized
    #         return JsonResponse({"error": "You do not have permission to access this resource."}, status=403)
        
    #     # Continue with your view logic if the user is authorized
    #     # For example:
    #     return JsonResponse({"message": "Success!"})

    queryset = Role.objects.all()
    serializer_class = RoleSerializer
   


class PermissionListCreateView(generics.ListCreateAPIView):

    # authentication_classes  = [PermissionMiddleware]
    # is_authorized_middleware = PermissionMiddleware()

    # def get(self, request, *args, **kwargs):
    #     # Check if the user is authorized
    #     if not self.is_authorized_middleware.has_permission(request):
    #         # Return an error response if the user is not authorized
    #         return JsonResponse({"error": "You do not have permission to access this resource."}, status=403)
        
    #     # Continue with your view logic if the user is authorized
    #     # For example:
    #     return JsonResponse({"message": "Success!"})

    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer


class PermissionRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):

    # authentication_classes  = [PermissionMiddleware]
    # is_authorized_middleware = PermissionMiddleware()

    # def get(self, request, *args, **kwargs):
    #     # Check if the user is authorized
    #     if not self.is_authorized_middleware.has_permission(request):
    #         # Return an error response if the user is not authorized
    #         return JsonResponse({"error": "You do not have permission to access this resource."}, status=403)
        
    #     # Continue with your view logic if the user is authorized
    #     # For example:
    #     return JsonResponse({"message": "Success!"})

    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

class RolePermissionListCreateView(generics.ListCreateAPIView):

    # permission_classes = [permissions.IsAuthenticated]
    # authentication_classes  = [PermissionMiddleware]

    queryset = RolePermission.objects.all()
    serializer_class = RolePermissionSerializer


class RolePermissionRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):

    # permission_classes = [permissions.IsAuthenticated]
    # is_authorized_middleware = PermissionMiddleware()

    # def get(self, request, *args, **kwargs):
    #     # Check if the user is authorized
    #     if not self.is_authorized_middleware.has_permission(request):
    #         # Return an error response if the user is not authorized
    #         return JsonResponse({"error": "You do not have permission to access this resource."}, status=403)
        
    #     # Continue with your view logic if the user is authorized
    #     # For example:
    #     return JsonResponse({"message": "Success!"})

    queryset = RolePermission.objects.all()
    serializer_class = RolePermissionSerializer


class UserPermissionListCreateView(generics.ListCreateAPIView):

    # is_authorized_middleware = PermissionMiddleware()

    # def get(self, request, *args, **kwargs):
    #     # Check if the user is authorized
    #     if not self.is_authorized_middleware.has_permission(request):
    #         # Return an error response if the user is not authorized
    #         return JsonResponse({"error": "You do not have permission to access this resource."}, status=403)
        
    #     # Continue with your view logic if the user is authorized
    #     # For example:
    #     return JsonResponse({"message": "Success!"})

    queryset = UserPermission.objects.all()
    serializer_class = UserPermissionSerilizer


class UserPermissionRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):

    # is_authorized_middleware = PermissionMiddleware()

    # def get(self, request, *args, **kwargs):
    #     # Check if the user is authorized
    #     if not self.is_authorized_middleware.has_permission(request):
    #         # Return an error response if the user is not authorized
    #         return JsonResponse({"error": "You do not have permission to access this resource."}, status=403)
        
    #     # Continue with your view logic if the user is authorized
    #     # For example:
    #     return JsonResponse({"message": "Success!"})

    queryset = UserPermission.objects.all()
    serializer_class = UserPermissionSerilizer


class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserRegrstrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({'msg': 'your registration is successfully complited'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and default_token_generator.check_token(user, token):
            user.is_verified = True
            user.save()
            return Response({'message': 'Email verification successfully complited.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid or expired verification link.'}, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):

    def post(self, request, formate=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')
            user = authenticate(request, username=email, password=password)
            if user is not None and user.is_verified:
                token = get_tokens_for_user(user)
                return Response({'token': token, 'msg': 'Login successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors': {'non_field_errors': ['email not validate or email or pwd are not validate']}}, status=status.HTTP_400_BAD_REQUEST)


# class UserDataView(APIView):
#     permission_classes = [permissions.IsAuthenticated]

#     def get(self, request, *args, **kwargs):
#         django_request = HttpRequest()
#         django_request.method = request.method
#         django_request.GET = request.query_params
#         django_request.POST = request.data
#         django_request.user = request.user
#         # Set this attribute to True to disable CSRF checks
#         django_request._dont_enforce_csrf_checks = True

#         middleware = ExampleMiddleware(get_response=self.dispatch)
#         response = middleware(django_request)
#         print(response)
#         if response is not True:
#              return response
    
#         serializer = UserDataViewSerializer(request.user)
#         return Response(serializer.data, status=status.HTTP_200_OK)
      
class UserDataView(APIView):

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):

        view_name = 'dataview'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request,view_name=view_name)
        # middleware(django_request,view_name=view_name)

        # if not isinstance(response, HttpResponse):
            # Middleware returned True, indicating user has permission
        if response.status_code == 200:    
            serializer = UserDataViewSerializer(request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return response
            # Middleware returned an error response
    
  

class AllUserDataView(APIView):

    permission_classes = [permissions.IsAuthenticated]
    

    # def get(self, request):
    #     django_request = HttpRequest()
    #     django_request.method = request.method
    #     django_request.GET = request.query_params
    #     django_request.POST = request.data
    #     django_request.user = request.user
    #     # Set this attribute to True to disable CSRF checks
    #     django_request._dont_enforce_csrf_checks = True

    #     middleware = ExampleMiddleware(get_response=self.dispatch)
    #     response = middleware(django_request)
    #     print(response)
    #     if response is not True:
    #          return response
        
    #     users = User.objects.all()
    #     serializer = AllUserDataViewSerializer(users, many=True)
    #     return Response(serializer.data, status=status.HTTP_200_OK)


class UserUpdateDetailsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, format=None):
        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request)
        print(response)
        if response is not True:
             return response
        
        seriazer = UserUpdateDetailsSerializer(
            data=request.data, context={'user': request.user})
        if seriazer.is_valid(raise_exception=True):
            return Response({'msg': 'User data updated successfully'}, status=status.HTTP_200_OK)
        return Response(seriazer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(
            data=request.data, context={'user': request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'password changed successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendPasswordResetEmailView(APIView):
    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': ' Email send successfully check your mail to verify'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserPasswordRestView(APIView):
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(
            data=request.data, context={'uid': uid, 'token': token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'password reseted successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserDeleteView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, format=None):
        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request)
        print(response)
        if response is not True:
             return response
        
        user = request.user  # Get authenticated user
        user.delete()
        return Response({'msg': 'User deleted successfully'}, status=status.HTTP_200_OK)
