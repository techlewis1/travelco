from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.models import User
from .models import UserProfile


# Serializer for retrieving user profile (GET)
class UserProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = UserProfile
        fields = ['username', 'email', 'travel_preferences', 'favorites']


# Serializer for user registration (POST)
class UserSerializer(serializers.HyperlinkedModelSerializer):
    email = serializers.EmailField(
        required=True,
        allow_blank=False,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    username = serializers.CharField(
        validators=[UniqueValidator(queryset=User.objects.all())]
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True, 'min_length': 8},
        }

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        user.is_active = False  # Example: require activation
        user.save()

        # Create UserProfile if not exists
        if not hasattr(user, 'userprofile'):
            UserProfile.objects.create(user=user)

        return user


# Serializer for updating user profile (PATCH/PUT)
class UserProfileUpdateSerializer(serializers.ModelSerializer):
    username = serializers.CharField(
        source='user.username',
        required=False,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    email = serializers.EmailField(
        source='user.email',
        required=False,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )

    class Meta:
        model = UserProfile
        fields = ['username', 'email', 'travel_preferences', 'favorites']

    def validate(self, attrs):
        user_data = attrs.get('user', {})
        user = self.instance.user

        username = user_data.get('username')
        email = user_data.get('email')

        if username and User.objects.exclude(pk=user.pk).filter(username=username).exists():
            raise serializers.ValidationError({'username': 'This username already exists.'})

        if email and User.objects.exclude(pk=user.pk).filter(email=email).exists():
            raise serializers.ValidationError({'email': 'This email is already taken.'})

        return attrs

    def update(self, instance, validated_data):
        # Update nested user fields
        user_data = validated_data.pop('user', {})
        user = instance.user

        username = user_data.get('username')
        if username:
            user.username = username

        email = user_data.get('email')
        if email:
            user.email = email

        user.save()

        # Update UserProfile fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        return instance
