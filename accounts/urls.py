from django.urls import path,include
from .views import *
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
urlpatterns=[
    path('',home,name='home'),
    path('about/',about, name='about'),
    path('signup.html',signup,name='signup'),
    path('login.html',signin,name='login'),
    path('profile.html',profile,name="profile"),
    path('forgot-password/',forgot_password,name="forgot_password"),
    path("logout/", logout_view, name="logout"),
    path('user-dashboard/', user_dashboard, name='user_dashboard'),
    # path('admin-dashboard/', admin_dashboard, name='admin_dashboard'),
    path("files/", include("files.urls")),
    path("share/<uuid:token>/", share_download, name="share_download"),
    path("verify-otp/", verify_otp, name="verify_otp"),
    path("accounts/activate/<uid>/<token>/",activate,name="activate",),
    path("audit-trail/",audit_trail,name="audit-trail"),
    path("profile/edit-profile/", edit_profile, name="edit_profile"),
    path("profile/change-password/", change_password, name="change_password"),
    path(
        "security/",
        include("security_ai.urls")
    ),
]
if settings.DEBUG:
    urlpatterns += static(
        settings.MEDIA_URL,
        document_root=settings.MEDIA_ROOT
    )