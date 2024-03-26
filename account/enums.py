from enum import Enum

class Endpoint(Enum):
    ROLES= 'roles'
    ROLE_CRUD = 'roles/<int:pk>/'
    PERMISSION = 'permission'
    PERMISSION_CRUD= 'permission/<int:pk>/'
    ROLE_PERMISSION = 'rolepermission'
    ROLE_PERMISSION_CRUD = 'rolepermission/<int:pk>/'
    USER_PERMISSION = 'userpermission'
    USER_PERMISSION_CRUD = 'userpermission/<int:pk>/'
    DATA_VIEW = 'dataview'
    ALL_USER_DATA_VIEW = 'alluserdataview'
    USER_UPDATE_DETAILS = 'userupdatedetails'
    CHANGE_PASSWORD = 'changepassword'
    SEND_RESET_PASSWORD_EMAIL = 'send-reset-password-email'
    RESET_PASSWORD = 'reset-password'
    USER_DELETE = 'userdelete'