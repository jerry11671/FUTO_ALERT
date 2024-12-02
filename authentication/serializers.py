from rest_framework import serializers
from .models import User
from django.contrib.auth import get_user_model

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True, required=True)
    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name',  'password', 'password2')
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')

        if password != password2:
            raise serializers.ValidationError("Passwords do not match!!")
        
        return data

    def create(self, validated_data):
        validated_data.pop('password2', None)
        if get_user_model().objects.filter(email=self.validated_data['email']):
            raise serializers.ValidationError({'error': 'Email already exists!'})
        
        
        user = User.objects.create_user(
            email = validated_data['email'],
            first_name = validated_data['first_name'],
            last_name = validated_data['last_name'],
            password = validated_data['password'],
        )
        user.is_active = True
        user.save()

        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()