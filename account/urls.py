
from django.urls import path 
from account.views import SendPasswordRestEmailView, UserChangePasswordView, UserLoginView, UserPasswordRestView, UserProfileView, UserRegistrationView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name="register"),
    path('login/', UserLoginView.as_view(), name="login"),
    path('profile/', UserProfileView.as_view(), name="profile"),
    path('changepassword/', UserChangePasswordView.as_view(), name="changepassword"),
    path('send-password-reset-email/', SendPasswordRestEmailView.as_view(), name="send-password-reset-email"),
    path('reset-password/<uid>/<token>/' , UserPasswordRestView.as_view() , name="reset-password")
]
