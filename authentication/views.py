from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User

from .serializers import UserRegistrationSerializer, LoginSerializer
from drf_spectacular.utils import extend_schema

tags = ["Auth"]

class RegisterUserView(GenericAPIView):
    serializer_class = UserRegistrationSerializer
    
    @extend_schema(
        summary="Registers a new user",
        description="This endpoint registers new user into FUTO_ALERT application",
        tags=tags,
        responses={201: UserRegistrationSerializer}
    )
    def post(self, request):
        data = request.data
        serializer = UserRegistrationSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            print(user)
            token = RefreshToken.for_user(user)
            return Response({
                'status': True,
                'data': serializer.data,
                'msg': 'Registration Successful!',
                'accessToken': str(token.access_token),
            }, status = status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class LoginUserView(GenericAPIView):
    serializer_class = LoginSerializer

    @extend_schema(
        summary="Authenticates a  user",
        description="This endpoint authenticates registered user into the FUTO_ALERT application",
        tags=tags,
        responses={201: LoginSerializer}
    )
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")   
        password = request.data.get('password')   
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'status': False,'msg': 'Invalid email'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not user:
            return Response({'status': False, 'msg': 'Invalid email'}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.check_password(password):
            return Response({'status': False, 'msg': 'Invalid password'})
        
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token

        response_data = {
            "message": "Log in successful",
            'access_token': str(access_token),
            "email": user.email,
            'first_name': user.first_name
        }

        return Response(response_data, status=status.HTTP_200_OK)