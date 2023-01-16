import datetime
import jwt
from users.models import User
from users.serializers import UserSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from dotenv import load_dotenv
import os

load_dotenv()


class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            payload = {
            'id': serializer.data["id"],
            'username': serializer.data["username"],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
            }

            token = jwt.encode(payload, os.getenv('JWT_SECRET'),
                           algorithm='HS256')
            return Response({
            'token': token,
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username', None)
        password = request.data.get('password', None)

        user = User.objects.filter(username=username).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'username': user.username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, os.getenv('JWT_SECRET'),
                           algorithm='HS256')

        return Response({
            'token': token,
        }, status=status.HTTP_200_OK)


class UserView(APIView):
    def get(self, request):
        token = request.headers.get('token')
        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, os.getenv(
                'JWT_SECRET'), algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Token invalid!')

        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)

        return Response(serializer.data, status=status.HTTP_200_OK)
