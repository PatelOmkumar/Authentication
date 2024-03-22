from django.urls import path
from account.views import UserRegistrationView, VerifyEmailView, UserLoginView, UserDataView, AllUserDataView, UserUpdateDetailsView, UserChangePasswordView, SendPasswordResetEmailView, UserPasswordRestView,  UserDeleteView,  RoleListCreateView, RoleRetrieveUpdateDestroyView, PermissionListCreateView, PermissionRetrieveUpdateDestroyView,RolePermissionListCreateView,RolePermissionRetrieveUpdateDestroyView,UserPermissionListCreateView,UserPermissionRetrieveUpdateDestroyView


urlpatterns = [
    path('roles/', RoleListCreateView.as_view(), name='role-list-create'),
    path('roles/<int:pk>/', RoleRetrieveUpdateDestroyView.as_view(),
         name='role-detail'),
    path('permission/', PermissionListCreateView.as_view(),),
    path('permission/<int:pk>/', PermissionRetrieveUpdateDestroyView.as_view(),),
     path('rolepermission/',RolePermissionListCreateView.as_view(),),
    path('rolepermission/<int:pk>/',RolePermissionRetrieveUpdateDestroyView.as_view(),),
     path('userpermission/',UserPermissionListCreateView.as_view(),),
     path('userpermission/<int:pk>/',UserPermissionRetrieveUpdateDestroyView.as_view(),),
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('verify/<str:uidb64>/<str:token>/',
         VerifyEmailView.as_view(), name='verify_email'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('dataview/', UserDataView.as_view(),
         name='UserDataViewSerializer'),
    path('alluserdataview/', AllUserDataView.as_view()),
    path('userupdatedetails/', UserUpdateDetailsView.as_view(),
         name='UserUpdateDetailsView'),
    path('changepassword/', UserChangePasswordView.as_view(),
         name='UserChangePasswordView'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(),
         name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordRestView.as_view()),
     # path('reset-password/', UserPasswordRestView.as_view()),
    path('userdelete/', UserDeleteView.as_view(), name='UserDeleteView'),
]
