from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsStaffOrReadOnly(BasePermission):
    """
    Wird z.B. in:
      - ManufacturerList
      - ProductList

    Erlaubt Lesezugriff (GET, HEAD, OPTIONS) für alle Benutzer.
    Schreibzugriff (POST, PUT, PATCH, DELETE) nur für Staff-Mitglieder.
    """

    def has_permission(self, request, view):
        is_staff = bool(request.user and request.user.is_staff)
        return is_staff or request.method in SAFE_METHODS


class IsAdminForDeleteOrPatchAndReadOnly(BasePermission):
    """
    Wird z.B. in:
      - ManufacturerDetail
      - ProductDetail

    Lesezugriff ist für alle erlaubt.
    PATCH/PUT: nur für Staff
    DELETE: nur für Superuser
    """
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True 
        elif request.method == 'DELETE':
            return bool(request.user and request.user.is_superuser)
        else:
            return bool(request.user and request.user.is_staff)


class IsOwnerOrAdmin(BasePermission):
    """
    Wird z.B. in:
      - ManufacturerUserDetail

    Lesezugriff ist für alle erlaubt.
    PATCH/PUT: nur durch den Besitzer (`obj.user`) oder Superuser
    DELETE: nur durch Superuser

    Hinweis: Das Objekt muss ein Attribut `user` haben.
    """
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        elif request.method == 'DELETE':
            return bool(request.user and request.user.is_superuser)
        else:
            return bool(request.user and request.user == obj.user)
