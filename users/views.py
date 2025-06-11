from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from rest_framework.response import Response
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.serializers import Serializer, CharField, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .models import EmailVerificationToken
from .permissions import IsOwner
from .serializers import UserSerializer, UserProfileSerializer, UserProfileUpdateSerializer

User = get_user_model()


def send_verification_email(user, request):
    token_obj = EmailVerificationToken.objects.create(user=user)
    verification_url = request.build_absolute_uri(
        reverse('email-verify', kwargs={'token': str(token_obj.token)})
    )
    message = (
        f"Hi {user.username},\n\n"
        f"Please verify your email by visiting this URL:\n\n"
        f"{verification_url}\n\n"
        f"Thanks!"
    )
    try:
        send_mail(
            'Verify your TravelCo account',
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email]
        )
    except Exception as e:
        print(f"Email send failed: {e}")
        raise


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, token):
        try:
            token_obj = EmailVerificationToken.objects.get(token=token)
        except EmailVerificationToken.DoesNotExist:
            return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)

        if token_obj.expires_at < timezone.now():
            return Response({'error': 'Token expired.'}, status=status.HTTP_410_GONE)

        user = token_obj.user
        user.is_active = True
        user.save()
        token_obj.delete()

        return Response({'message': 'Email verified successfully.'}, status=status.HTTP_200_OK)


class RegisterUserView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save(is_active=False)
        try:
            send_verification_email(user, self.request)
        except Exception:
            # Let the user be created, but notify about email failure
            # Log this properly in production
            pass

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        user_data = response.data
        return Response({
            'message': 'User registered successfully. Please check your email to verify your account.',
            'user': {
                'username': user_data.get('username'),
                'email': user_data.get('email')
            }
        }, status=status.HTTP_201_CREATED)


class ResendVerificationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        if user.is_active:
            return Response({'message': 'User is already verified.'}, status=status.HTTP_200_OK)

        EmailVerificationToken.objects.filter(user=user).delete()

        try:
            send_verification_email(user, request)
        except Exception:
            return Response(
                {'error': 'Failed to send verification email.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response({'message': 'Verification email resent.'}, status=status.HTTP_200_OK)


class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated, IsOwner]

    def get_serializer_class(self):
        if self.request.method in ['PUT', 'PATCH']:
            return UserProfileUpdateSerializer
        return UserProfileSerializer

    def get_object(self):
        return self.request.user.userprofile
    
    def get(self, request, *args, **kwargs):
        profile = self.get_object()
        self.check_object_permissions(request, profile)
        serializer = UserProfileSerializer(profile)
        return Response(serializer.data)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get('refresh')

        if not refresh_token:
            return Response(
                {"detail": "Refresh token is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except TokenError:
            return Response(
                {"detail": "Invalid or expired token."},
                status=status.HTTP_400_BAD_REQUEST
            )


class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]

    class DeleteAccountSerializer(Serializer):
        password = CharField(write_only=True)

        def validate_password(self, value):
            user = self.context['request'].user
            if not user.check_password(value):
                raise ValidationError(_("Incorrect password."))
            return value

    def delete(self, request):
        serializer = self.DeleteAccountSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        user = request.user
        hard_delete = request.query_params.get('hard', 'false').lower() == 'true'

        if hard_delete:
            user.delete()
            return Response({'message': 'Account permanently deleted.'}, status=status.HTTP_204_NO_CONTENT)
        else:
            user.is_active = False
            user.save()
            return Response({'message': 'Account deactivated (soft delete).'}, status=status.HTTP_200_OK)


class ReactivateAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        password = request.data.get('password')

        if not password:
            return Response({'password': 'This field is required.'}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(password):
            return Response({'password': 'Incorrect password.'}, status=status.HTTP_400_BAD_REQUEST)

        user.is_active = True
        user.save()

        return Response({'message': 'Account reactivated successfully.'}, status=status.HTTP_200_OK)
