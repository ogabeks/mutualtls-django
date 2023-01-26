from django.http import HttpResponseForbidden
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class ClientCertificateMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.META.get('HTTP_X_CLIENT_CERT'):
            return HttpResponseForbidden()

        cert_data = request.META.get('HTTP_X_CLIENT_CERT')

        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        if not cert.is_valid():
            return HttpResponseForbidden()

        response = self.get_response(request)
        return response
