from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from account.serializers import SendPasswordResetEmailSerializer, UserChangePasswordSerializer, UserLoginSerializer, UserPasswordResetSerializer, UserProfileSerializer, UserRegistrationSerializer
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

# Create your views here.
#genrating tokens manually 
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh':str(refresh),
        'access':str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self ,request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token =get_tokens_for_user(user)
            return Response({'token':token,'msg':'Registraion Successfull'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors , status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self,request,format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password = password)
            if user is not None:
                token=get_tokens_for_user(user)
                return Response({'token':token,'msg':'Login Successfull'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors':{'non_field_errors': ['email or password is not valid']}}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors , status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes=[IsAuthenticated]
    def get(self ,request, format=None):
       serializer = UserProfileSerializer(request.user)
       return Response(serializer.data , status=status.HTTP_200_OK)
    
class UserChangePasswordView(APIView):
    renderer_classes=[UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request , format = None):
      serializer = UserChangePasswordSerializer(data=request.data , context ={'user':request.user})
      if serializer.is_valid(raise_exception=True):
        return Response({'msg':'password change successfully'}, status=status.HTTP_200_OK)
      return Response(serializer.errors , status=status.HTTP_400_BAD_REQUEST)

class SendPasswordRestEmailView(APIView):
    renderer_classes =[UserRenderer]
    def post(self , request , format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password reset email Sent successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors , status=status.HTTP_400_BAD_REQUEST)

class UserPasswordRestView(APIView):
    renderer_classes =[UserRenderer]
    def post(self , request , uid , token , format= None):
        serializer = UserPasswordResetSerializer(data = request.data , context={'user': request.user ,'uid':uid , 'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password Reset successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors , status=status.HTTP_400_BAD_REQUEST)
        
            





       