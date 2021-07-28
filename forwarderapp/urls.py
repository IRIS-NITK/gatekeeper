from django.urls import include, path, re_path
from rest_framework import routers

from . import views

# router = routers.DefaultRouter()
# router.register(r'users', views.UserViewSet)

urlpatterns = [
    # path('', include(router.urls)),
    path('connections', views.Connections.as_view()),
    path('connections/', views.Connections.as_view()),
    path('connections/<int:id>/renew', views.Renew.as_view()),
    path('connections/<int:id>/renew/', views.Renew.as_view()),
    path('connections/<int:id>/expire', views.Expire.as_view()),
    path('connections/<int:id>/expire/', views.Expire.as_view()),
    path('connections/<int:id>', views.Connection.as_view()),
    path('connections/<int:id>/', views.Connection.as_view()),
    # path('ports/', views.ports),
    # path('ports/<int:port_number>/', views.port),
    # path('statistics/', views.statistics),
    # path('api-auth/', include('rest_framework.urls', namespace='rest_framework'))
]
