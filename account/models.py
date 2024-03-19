from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

from authenv import settings

# Create your models here.


class Role(models.Model):
    role_id = models.AutoField(primary_key=True)
    role_name = models.CharField(max_length=100, unique=True)


class Permission(models.Model):
    permission_id = models.AutoField(primary_key=True)
    permission_name = models.CharField(max_length=255, unique=True)
    permission_description = models.CharField(max_length=200)


class RolePermission(models.Model):
    role_id = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission_id = models.ForeignKey(Permission, on_delete=models.CASCADE)


class UserPermission(models.Model):
    id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE )
    permission_id = models.ForeignKey(Permission,on_delete=models.CASCADE)

# custom user manager


class UserManager(BaseUserManager):
    def create_user(self, email, name, phone, date_of_birth, gender, address, role_id=None, password=None, password2=None):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError("Users must have an email address")

        default_role = Role.objects.get(role_id=4)

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            phone=phone,
            date_of_birth=date_of_birth,
            gender=gender,
            address=address,
            role_id=default_role,
        )
        user.set_password(password)
        # user.role_id_id = role_id
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, phone, date_of_birth, gender, address, password=None):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email=email,
            password=password,
            name=name,
            phone=phone,
            date_of_birth=date_of_birth,
            gender=gender,
            address=address,
            # role_id=1
        )
        user.is_superuser = True
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    id = models.AutoField(primary_key=True)
    email = models.EmailField(
        verbose_name="Email",
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=200)
    phone = models.CharField(max_length=12)
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=10, choices=[(
        'male', 'Male'), ('female', 'Female'), ('other', 'Other')], null=True, blank=True)
    address = models.TextField(null=True, blank=True)
    role_id = models.ForeignKey(Role, on_delete=models.CASCADE)

    is_superuser = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "phone", "date_of_birth", "gender", "address"]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin
