from rest_framework import permissions

class IsOwner(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to access or edit it.
    Assumes the object has a 'user' attribute.
    """

    def has_object_permission(self, request, view, obj):
        return obj.user == request.user
