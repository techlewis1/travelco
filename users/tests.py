from unittest.mock import patch
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth import get_user_model
from users.models import EmailVerificationToken
from rest_framework_simplejwt.tokens import RefreshToken
from users.models import UserProfile
import uuid

User = get_user_model()


class UserRegistrationTests(APITestCase):
    def setUp(self):
        self.register_url = reverse('register')

    def test_register_user_success(self):
        data = {
            "username": "testuser",
            "email": "testuser@example.com",
            "password": "strongpassword123"
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['user']['username'], data['username'])
        self.assertEqual(response.data['user']['email'], data['email'])
        self.assertTrue(User.objects.filter(username="testuser").exists())

    def test_register_user_missing_fields(self):
        data = {
            "username": "",
            "email": "invalidemail",
            # missing password
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', response.data)
        self.assertIn('password', response.data)

    def test_register_user_duplicate_username(self):
        User.objects.create_user(username='testuser', email='a@b.com', password='pass1234')
        data = {
            "username": "testuser",
            "email": "newemail@example.com",
            "password": "newpass123"
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', response.data)


class EmailVerificationTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='verifyuser',
            email='verifyuser@example.com',
            password='strongpass123',
            is_active=False
        )
        self.token = str(uuid.uuid4())
        EmailVerificationToken.objects.create(user=self.user, token=self.token)

    def test_verify_email_success(self):
        verify_url = reverse('email-verify', kwargs={'token': self.token})
        response = self.client.get(verify_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertFalse(EmailVerificationToken.objects.filter(token=self.token).exists())

    def test_verify_email_invalid_token(self):
        invalid_token = str(uuid.uuid4())
        verify_url = reverse('email-verify', kwargs={'token': invalid_token})
        response = self.client.get(verify_url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UserLoginTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='loginuser', email='loginuser@example.com', password='password123')
        self.login_url = reverse('token_obtain_pair')

    def test_login_success(self):
        data = {
            "username": "loginuser",
            "password": "password123"
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_login_wrong_password(self):
        data = {
            "username": "loginuser",
            "password": "wrongpassword"
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class ResendVerificationEmailTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='testpass123',
            is_active=False
        )
        self.active_user = User.objects.create_user(
            username='activeuser',
            email='activeuser@example.com',
            password='testpass123',
            is_active=True
        )
        self.url = reverse('resend-verification')

    def test_resend_verification_email_success(self):
        data = {'email': 'testuser@example.com'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Verification email resent', response.data['message'])
        tokens = EmailVerificationToken.objects.filter(user=self.user)
        self.assertTrue(tokens.exists())

    def test_resend_verification_email_missing_email(self):
        response = self.client.post(self.url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Email is required', response.data['error'])

    def test_resend_verification_email_user_not_found(self):
        data = {'email': 'nonexistent@example.com'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('User not found', response.data['error'])

    def test_resend_verification_email_user_already_active(self):
        data = {'email': 'activeuser@example.com'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('User is already verified.', response.data['message'])


class UserLogoutTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='logoutuser', email='logout@example.com', password='testpassword123')
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)
        self.refresh_token = str(refresh)
        self.logout_url = reverse('token_logout')

    def test_logout_success(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        response = self.client.post(self.logout_url, data={'refresh': self.refresh_token}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)  # Fixed expected status

    def test_logout_missing_token(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        response = self.client.post(self.logout_url, data={}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('refresh', response.data)
        self.assertIn('This field is required.', response.data['refresh'][0])

    def test_logout_invalid_token(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        response = self.client.post(self.logout_url, data={'refresh': 'invalidtoken'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Fixed expected status
        self.assertIn('detail', response.data)


class AccountDeletionTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='deleteuser', email='delete@example.com', password='deletepass123')
        self.url = reverse('delete-account')
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)

    def authenticate(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')

    def test_soft_delete_account(self):
        self.authenticate()
        response = self.client.delete(self.url, data={'password': 'deletepass123'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)

    def test_hard_delete_account(self):
        self.authenticate()
        response = self.client.delete(f"{self.url}?hard=true", data={'password': 'deletepass123'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(User.objects.filter(username='deleteuser').exists())

    def test_delete_account_wrong_password(self):
        self.authenticate()
        response = self.client.delete(self.url, data={'password': 'wrongpass'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

    def test_delete_account_unauthenticated(self):
        response = self.client.delete(self.url, data={'password': 'deletepass123'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class UserReactivationTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='softdeleteduser',
            email='softdeleted@example.com',
            password='reactivatepass123',
            is_active=True
        )
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)

        self.user.is_active = False
        self.user.save()

        self.url = reverse('reactivate-account')

    def authenticate(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')

    @patch('rest_framework_simplejwt.authentication.JWTAuthentication.get_user')
    def test_reactivate_account_success(self, mock_get_user): 
        mock_get_user.return_value = self.user
        self.authenticate()
        data = {'password': 'reactivatepass123'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)

    @patch('rest_framework_simplejwt.authentication.JWTAuthentication.get_user')
    def test_reactivate_account_wrong_password(self, mock_get_user):
        mock_get_user.return_value = self.user
        self.authenticate()
        data = {'password': 'wrongpassword'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

    def test_reactivate_account_unauthenticated(self):
        data = {'password': 'reactivatepass123'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

class UserProfileTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='profileuser',
            email='profileuser@example.com',
            password='profilepass123'
        )
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)
        self.profile_url = reverse('profile') 

    def authenticate(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')

    def test_view_profile_authenticated(self):
        self.authenticate()
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], self.user.username)
        self.assertEqual(response.data['email'], self.user.email)

    def test_view_profile_unauthenticated(self):
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_profile_success(self):
        self.authenticate()
        data = {
            'username': 'updateduser',
            'email': 'updated@example.com'
        }
        response = self.client.patch(self.profile_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, 'updateduser')
        self.assertEqual(self.user.email, 'updated@example.com')

    def test_update_profile_unauthenticated(self):
        data = {'username': 'updateduser'}
        response = self.client.patch(self.profile_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_profile_invalid_email(self):
        self.authenticate()
        data = {'email': 'not-an-email'}
        response = self.client.patch(self.profile_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

def test_unauthenticated_cannot_access_profile(self):
    response = self.client.get(self.profile_url)
    self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

def test_user_cannot_access_other_users_profile(self):
    other_user = User.objects.create_user(username='otheruser', password='pass123')
    other_profile = other_user.userprofile

    self.authenticate()  # logged in as self.user
    # Try to get other user's profile URL, e.g. /profiles/{other_profile.id}/
    url = reverse('profile-detail', kwargs={'pk': other_profile.pk})
    response = self.client.get(url)
    self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
