
from xml.dom import ValidationErr
from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str , force_bytes , DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode , urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from account import utils
from email import utils


#create Your serialzer classes Here 

class UserRegistrationSerializer(serializers.ModelSerializer):
    #we are creating this model for user resigatraions and authentications
    password2 = serializers.CharField(style={'input_type':'password'}, write_only =True)
    class Meta:
        model = User
        fields = ['email','name','password','password2','tc']
        extra_kwargs ={
            'password':{'write_only':True}
        }
        

    #validatin the password and confirm password2 while registarions 
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        print(attrs)
        if password != password2:
            raise serializers.ValidationError("Oops!! password and confirm password does not match")
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length = 255)
    class Meta:
        model = User
        fields = ['email','password']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model= User
        fields = ['id','email','name']


class UserChangePasswordSerializer(serializers.Serializer):
   password = serializers.CharField(max_length=255 , style={'input_type':'password'}, write_only =True)
   password2 = serializers.CharField(max_length=255 , style={'input_type':'password'}, write_only =True)
   class Meta:
    Feilds = ["password" , "password2"]
   
   def validate(self, attrs):
    password = attrs.get('password')
    password2 = attrs.get('password2')
    user = self.context.get('user')
    if password != password2:
        raise serializers.ValidationError("password and confirm password doesn't match")
    user.set_password(password)
    user.save()
    return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=255)
    class Meta:
        fields =["email"]

    def validate(self, attrs):
        email = attrs.get("email")
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print("Encoded UID" , uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print("password reset token" , token)
            link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
            print("Password reset Link" , link)
            #send Email 
            body = 'Click following link to Reset your password '+ link
            data = {
                'subject':'Reset Your Password' , 
                'body' : body , 
                'to_email':user.email
            }
            utils.send_email(data)
            return attrs
        else:
            raise ValidationErr("You are not a Registered User")
        return super().validate(attrs)

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255 , style={'input_type':'password'}, write_only =True)
    password2 = serializers.CharField(max_length=255 , style={'input_type':'password'}, write_only =True)
    class Meta:
        Feilds = ["password" , "password2"]
   
    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            user = self.context.get('user')
            if password != password2:
                raise serializers.ValidationError("password and confirm password doesn't match")
            id =smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user , token):
                raise ValidationErr("Token is not valid or Expired")
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user , token)
            raise ValidationErr("token is not valid or expired")
