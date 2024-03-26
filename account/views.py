from django.http import HttpRequest, HttpResponse, JsonResponse
from rest_framework import generics
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
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from django.http import JsonResponse

# generate token manually


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class RoleListCreateView(generics.ListCreateAPIView):

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = RoleSerializer
    queryset = Role.objects.all()

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', RoleSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        view_name = 'roles'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            queryset = self.get_queryset()
            serializer = self.serializer_class(queryset, many=True)
            return JsonResponse(serializer.data, safe=False)
        else:
            return response

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'role_name': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['role_name'],
        ),
        responses={
            201: openapi.Response('Response description', RoleSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def post(self, request, *args, **kwargs):

        view_name = 'roles'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:

            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, status=200)
            else:
                return JsonResponse(serializer.errors, status=400)
        else:
            return response


class RoleRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):

    permission_classes = [permissions.IsAuthenticated]
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'role_name': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['role_name'],
        ),
        responses={
            200: openapi.Response('Response description', RoleSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def put(self, request, *args, **kwargs):

        view_name = 'roles/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            serializer = self.serializer_class(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, status=200)
            else:
                return JsonResponse(serializer.errors, status=400)
        else:
            return response

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'role_name': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=[],
        ),
        responses={
            200: openapi.Response('Response description', RoleSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def patch(self, request, *args, **kwargs):
        view_name = 'roles/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            serializer = self.serializer_class(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, status=200)
            else:
                return JsonResponse(serializer.errors, status=400)
        else:
            return response

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', RoleSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request, *args, **kwargs):

        view_name = 'roles/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            # pk = kwargs.get('pk')
            instance = self.get_object()
            serializer = self.serializer_class(instance)
            return JsonResponse(serializer.data)
        else:
            return response

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', RoleSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def delete(self, request, *args, **kwargs):

        view_name = 'roles/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            # pk = kwargs.get('pk')
            instance = self.get_object()
            self.perform_destroy(instance)
            return JsonResponse({'msg': 'deleted'})
        else:
            return response


class PermissionListCreateView(generics.ListCreateAPIView):

    permission_classes = [permissions.IsAuthenticated]
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', PermissionSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        view_name = 'permission'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            queryset = self.get_queryset()
            serializer = self.serializer_class(queryset, many=True)
            return JsonResponse(serializer.data, safe=False)
        else:
            return response

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'permission_name': openapi.Schema(type=openapi.TYPE_STRING),
                'permission_description': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['permission_name', 'permission_description'],
        ),
        responses={
            201: openapi.Response('Response description', PermissionSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def post(self, request, *args, **kwargs):
        view_name = 'permission'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, safe=False)
            else:
                return JsonResponse(serializer.errors, status=400)
        else:
            return response


class PermissionRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):

    permission_classes = [permissions.IsAuthenticated]

    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'permission_name': openapi.Schema(type=openapi.TYPE_STRING),
                'permission_description': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['permission_name', 'permission_description'],
        ),
        responses={
            200: openapi.Response('Response description', PermissionSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def put(self, request, *args, **kwargs):
        view_name = 'permission/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            serializer = self.serializer_class(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, status=200)
            else:
                return JsonResponse(serializer.errors, status=400)
        else:
            return response

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'permission_name': openapi.Schema(type=openapi.TYPE_STRING),
                'permission_description': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['permission_name', 'permission_description'],
        ),
        responses={
            200: openapi.Response('Response description', PermissionSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def patch(self, request, *args, **kwargs):
        view_name = 'permission/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            serializer = self.serializer_class(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, status=200)
            else:
                return JsonResponse(serializer.errors, status=400)
        else:
            return response

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', PermissionSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        view_name = 'permission/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            serializer = self.serializer_class(instance)
            return JsonResponse(serializer.data, status=200)
        else:
            return response

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', PermissionSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def delete(self, request, *args, **kwargs):
        view_name = 'permission/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            self.perform_destroy(instance)
            return JsonResponse({'msg': 'deleted'})
        else:
            return response


class RolePermissionListCreateView(generics.ListCreateAPIView):

    permission_classes = [permissions.IsAuthenticated]
    queryset = RolePermission.objects.all()
    serializer_class = RolePermissionSerializer

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', RolePermissionSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        view_name = 'rolepermission'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            queryset = self.get_queryset()
            serializer = self.serializer_class(queryset, many=True)
            return JsonResponse(serializer.data, safe=False)
        else:
            return response

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'role_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'permission_id': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
            required=['role_id', 'permission_id'],
        ),
        responses={
            201: openapi.Response('Response description', RolePermissionSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def post(self, request, *args, **kwargs):
        view_name = 'rolepermission'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:

            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, status=201)
            else:
                return JsonResponse(serializer.errors, status=400)
        else:
            return response


class RolePermissionRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):

    permission_classes = [permissions.IsAuthenticated]

    queryset = RolePermission.objects.all()
    serializer_class = RolePermissionSerializer

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'role_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'permission_id': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
            required=['role_id', 'permission_id'],
        ),
        responses={
            200: openapi.Response('Response description', RolePermissionSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def put(self, request, *args, **kwargs):
        view_name = 'rolepermission/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            serializer = self.serializer_class(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, status=201)
            else:
                return JsonResponse(serializer.errors, status=400)
        else:
            return response

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'role_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'permission_id': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
            required=['role_id', 'permission_id'],
        ),
        responses={
            200: openapi.Response('Response description', RolePermissionSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def patch(self, request, *args, **kwargs):
        view_name = 'rolepermission/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            serializer = self.serializer_class(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, status=200)
            else:
                return JsonResponse(serializer.errors, status=400)
        else:
            return response

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', RolePermissionSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        view_name = 'rolepermission/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            serializer = self.serializer_class(instance)
            return JsonResponse(serializer.data, status=200)
        else:
            return response

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', RolePermissionSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def delete(self, request, *args, **kwargs):
        view_name = 'permission/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            self.perform_destroy(instance)
            return JsonResponse({'msg': 'deleted'})
        else:
            return response


class UserPermissionListCreateView(generics.ListCreateAPIView):

    permission_classes = [permissions.IsAuthenticated]

    queryset = UserPermission.objects.all()
    serializer_class = UserPermissionSerilizer

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', UserPermissionSerilizer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        view_name = 'userpermission'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            queryset = self.get_queryset()
            serializer = self.serializer_class(queryset, many=True)
            return JsonResponse(serializer.data, safe=False)
        else:
            return response

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'user_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'permission_id': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
            required=['user_id', 'permission_id'],
        ),
        responses={
            201: openapi.Response('Response description', UserPermissionSerilizer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def post(self, request, *args, **kwargs):
        view_name = 'userpermission'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, status=200)
            else:
                return JsonResponse(serializer.errors, status=400)
        else:
            return response


class UserPermissionRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):

    permission_classes = [permissions.IsAuthenticated]

    queryset = UserPermission.objects.all()
    serializer_class = UserPermissionSerilizer

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'user_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'permission_id': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
            required=['user_id', 'permission_id'],
        ),
        responses={
            200: openapi.Response('Response description', UserPermissionSerilizer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def put(self, request, *args, **kwargs):
        view_name = 'userpermission/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            serializer = self.serializer_class(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, safe=False)
            else:
                return JsonResponse(serializer.errors, status=400)
        else:
            return response

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'user_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'permission_id': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
            required=['user_id', 'permission_id'],
        ),
        responses={
            200: openapi.Response('Response description', UserPermissionSerilizer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def patch(self, request, *args, **kwargs):
        view_name = 'userpermission/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            serializer = self.serializer_class(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, safe=False)
            else:
                return JsonResponse(serializer.errors, status=400)
        else:
            return response

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', UserPermissionSerilizer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        view_name = 'userpermission/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            serializer = self.serializer_class(instance)
            return JsonResponse(serializer.data, safe=False)
        else:
            return response

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', UserPermissionSerilizer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description='Bearer token',
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def delete(self, request, *args, **kwargs):
        view_name = 'userpermission/<int:pk>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            instance = self.get_object()
            self.perform_destroy(instance)
            return JsonResponse({'msg': 'deleted'})
        else:
            return response


class UserRegistrationView(APIView):

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'phone': openapi.Schema(type=openapi.TYPE_STRING),
                'date_of_birth': openapi.Schema(type=openapi.TYPE_STRING),
                'gender': openapi.Schema(type=openapi.TYPE_STRING),
                'address': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
                'password2': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['email', 'name', 'phone', 'date_of_birth',
                      'gender', 'address', 'password', 'password2'],
        ),
        responses={
            200: openapi.Response('Response description', UserRegrstrationSerializer),
            400: "Bad request",
        }
    )
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

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=["email", "password"],
        ),
        responses={
            200: openapi.Response('Response description', UserLoginSerializer),
            400: "Bad request",
        }
    )
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


class UserDataView(APIView):

    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', UserDataViewSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',  # Name of the parameter
                openapi.IN_HEADER,  # Location of the parameter in the request
                description='Bearer token',  # Description of the parameter
                type=openapi.TYPE_STRING,  # Type of the parameter
                required=True,  # Whether the parameter is required
            )
        ]
    )
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
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            serializer = UserDataViewSerializer(request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return response
            # Middleware returned an error response


class AllUserDataView(APIView):

    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description', AllUserDataViewSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',  # Name of the parameter
                openapi.IN_HEADER,  # Location of the parameter in the request
                description='Bearer token',  # Description of the parameter
                type=openapi.TYPE_STRING,  # Type of the parameter
                required=True,  # Whether the parameter is required
            )
        ]
    )
    def get(self, request, *args, **kwargs):
        view_name = 'alluserdataview'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:

            users = User.objects.all()
            serializer = AllUserDataViewSerializer(users, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return response
            # Middleware returned an error response


class UserUpdateDetailsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.FORMAT_EMAIL),
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'phone': openapi.Schema(type=openapi.TYPE_STRING),
                'date_of_birth': openapi.Schema(type=openapi.FORMAT_DATE),
                'gender': openapi.Schema(type=openapi.TYPE_STRING),
                'address': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.FORMAT_PASSWORD),
                'password2': openapi.Schema(type=openapi.FORMAT_PASSWORD),
            },
            required=['email', 'name', 'phone', 'date_of_birth',
                      'gender', 'address', 'password', 'password2'],
        ),
        responses={
            200: openapi.Response('Response description', UserUpdateDetailsSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',  # Name of the parameter
                openapi.IN_HEADER,  # Location of the parameter in the request
                description='Bearer token',  # Description of the parameter
                type=openapi.TYPE_STRING,  # Type of the parameter
                required=True,  # Whether the parameter is required
            )
        ]
    )
    def put(self, request, format=None):

        view_name = 'userupdatedetails'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            seriazer = UserUpdateDetailsSerializer(
                data=request.data, context={'user': request.user})
            if seriazer.is_valid(raise_exception=True):
                return Response({'msg': 'User data updated successfully'}, status=status.HTTP_200_OK)
            return Response(seriazer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return response


class UserChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'old_password': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
                'password2': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['old_password', 'password', 'password2'],
        ),
        responses={
            200: openapi.Response('Response description', UserChangePasswordSerializer),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',  # Name of the parameter
                openapi.IN_HEADER,  # Location of the parameter in the request
                description='Bearer token',  # Description of the parameter
                type=openapi.TYPE_STRING,  # Type of the parameter
                required=True,  # Whether the parameter is required
            )
        ]
    )
    def post(self, request, format=None):

        view_name = 'changepassword'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            serializer = UserChangePasswordSerializer(
                data=request.data, context={'user': request.user})
            if serializer.is_valid(raise_exception=True):
                return Response({'msg': 'password changed successfully'}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return response


class SendPasswordResetEmailView(APIView):

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.FORMAT_EMAIL)
            },
            required=['email'],
        ),
        responses={
            200: openapi.Response('Response description', SendPasswordResetEmailSerializer),
            400: "Bad request",
        }
    )
    def post(self, request, format=None):

        view_name = 'send-reset-password-email'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            serializer = SendPasswordResetEmailSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                return Response({'msg': ' Email send successfully check your mail to verify'}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return response


class UserPasswordRestView(APIView):

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'password': openapi.Schema(type=openapi.TYPE_STRING),
                'password2': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['password', 'password2'],
        ),
        responses={
            200: openapi.Response('Response description', UserPasswordResetSerializer),
            400: "Bad request",
        },
    )
    def post(self, request, uid, token, format=None):

        view_name = 'reset-password/<uid>/<token>/'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:
            serializer = UserPasswordResetSerializer(
                data=request.data, context={'uid': uid, 'token': token})
            if serializer.is_valid(raise_exception=True):
                return Response({'msg': 'password reseted successfully'}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return response


class UserDeleteView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Response description'),
            400: "Bad request",
        },
        manual_parameters=[
            openapi.Parameter(
                'Authorization',  # Name of the parameter
                openapi.IN_HEADER,  # Location of the parameter in the request
                description='Bearer token',  # Description of the parameter
                type=openapi.TYPE_STRING,  # Type of the parameter
                required=True,  # Whether the parameter is required
            )
        ]
    )
    def delete(self, request, format=None):

        view_name = 'userdelete'

        django_request = HttpRequest()
        django_request.method = request.method
        django_request.GET = request.query_params
        django_request.POST = request.data
        django_request.user = request.user
        # Set this attribute to True to disable CSRF checks
        django_request._dont_enforce_csrf_checks = True

        middleware = ExampleMiddleware(get_response=self.dispatch)
        response = middleware(django_request, view_name=view_name)

        if response.status_code == 200:

            user = request.user  # Get authenticated user
            user.delete()
            return Response({'msg': 'User deleted successfully'}, status=status.HTTP_200_OK)
        else:
            return response
