# users/views.py
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from rest_framework.response import Response
from rest_framework import generics, status
from .models import EmailVerificationToken
from rest_framework.views import APIView
from django.utils import timezone
from rest_framework.permissions import AllowAny, IsAuthenticated
from .serializers import UserSerializer, UserProfileSerializer

class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, token):
        try:
            token_obj = EmailVerificationToken.objects.get(token=token)
        except EmailVerificationToken.DoesNotExist:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        
        if token_obj.expires_at < timezone.now():
            return Response({'error': 'Token expired'}, status=status.HTTP_404_BAD_REQUEST)
        
        user = token_obj.user
        user.is_active = True
        user.save()

        # Delete token after successful verification
        token_obj.delete()
        return Response({'message': 'Email verified successfully'}, status=status.HTTP_200_OK)

class RegisterUserView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()

        # Create email verification token
        token_obj = EmailVerificationToken.objects.create(user=user)

        # Build verification url 
        verification_url = self.request.build_absolute_uri(
            reverse('email-verify', kwargs={'token': token_obj.token})
        )

        # Send email (Email_backend should be configured)
        subject = 'Please verify your TravelCo account'
        message = f'Hi {user.username},\n\nPlease click the link below to verify your account:\n\n{verification_url}\n\nThanks!'
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [user.email]


        send_mail(subject, message, from_email, recipient_list)

class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user.userprofile
