#!/usr/bin/env python3

import base64
import os
import sys

# Add the parent directory to the Python path so we can import the library
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from libcbv2g_snake import (
    Iso2ExiMessage,
    CertificateInstallationReq,
    CertificateInstallationRes,
    RootCertificateID,
    CertificateChain,
    SubCertificate,
    EncryptedPrivateKey
)

def test_certificate_installation():
    # Create an instance of the EXI message handler
    exi_handler = Iso2ExiMessage()

    # Test Certificate Installation Request
    print("\nTesting Certificate Installation Request:")
    print("-" * 50)

    # Create a request object
    request = CertificateInstallationReq(
        SessionID="1234567890ABCDEF",
        Id="ID1",
        OEMProvisioningCert="MIIBmDCCAQGgAwIBAgIBATAKBggqhkjOPQQDAjAzMRwwGgYDVQQKDBNPRU0gUHJvdmlzaW9uaW5nIENBMRMwEQYDVQQDDApPRU0gU3ViIENBMB4XDTIzMDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowKzEMMAoGA1UECgwDT0VNMRswGQYDVQQDDBJPRU0gUHJvdmlzaW9uaW5nIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY30s8rpA+KJ+YcgiYtIEJjaOV0xkiCGZXak3JTt6OcIgC3681KIByqcU7Jg/xkBxDv3O9KgP83KH9IrPNldFQaMjMCEwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJ6s6R7zzk6WHEQbK8nQ09u3qfPP2xAZu6VPGVYPbXvKAiBqlxhBvW8QOu1J5ZAYtrV7KxHD7zKJtOEfZkY9Qh5y1Q==",
        ListOfRootCertificateIDs=[
            RootCertificateID(
                X509IssuerName="CN=V2G Root CA, O=V2G PKI",
                X509SerialNumber=1234567890
            )
        ]
    )

    # Encode the request to EXI
    exi_bytes = exi_handler.EncodeCertReq(request)
    print("Request encoded to EXI successfully")

    # Convert to base64 for demonstration
    base64_exi = base64.b64encode(exi_bytes).decode('utf-8')
    print(f"Base64 encoded EXI: {base64_exi[:50]}...")

    # Decode back to request object
    decoded_request = exi_handler.DecodeCertReq(base64_exi)
    print("Request decoded from EXI successfully")
    print(f"Decoded SessionID: {decoded_request.SessionID}")
    print(f"Decoded Id: {decoded_request.Id}")

    # Test Certificate Installation Response
    print("\nTesting Certificate Installation Response:")
    print("-" * 50)

    # Create a response object
    response = CertificateInstallationRes(
        SessionID="1234567890ABCDEF",
        ResponseCode="OK",
        SAProvisioningCertificateChain=CertificateChain(
            Certificate="MIIBmDCCAQGgAwIBAgIBATAKBggqhkjOPQQDAjAzMRwwGgYDVQQKDBNTQSBQcm92aXNpb25pbmcgQ0ExEzARBgNVBAMMClNBIFN1YiBDQTAeFw0yMzAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMCsxDDAKBgNVBAoMA1NBTTEbMBkGA1UEAwwSU0EgUHJvdmlzaW9uaW5nIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY30s8rpA+KJ+YcgiYtIEJjaOV0xkiCGZXak3JTt6OcIgC3681KIByqcU7Jg/xkBxDv3O9KgP83KH9IrPNldFQaMjMCEwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJ6s6R7zzk6WHEQbK8nQ09u3qfPP2xAZu6VPGVYPbXvKAiBqlxhBvW8QOu1J5ZAYtrV7KxHD7zKJtOEfZkY9Qh5y1Q==",
            SubCertificates=[
                SubCertificate(
                    Certificate="MIIBmDCCAQGgAwIBAgIBATAKBggqhkjOPQQDAjAzMRwwGgYDVQQKDBNTQSBQcm92aXNpb25pbmcgQ0ExEzARBgNVBAMMClNBIFJvb3QgQ0EwHhcNMjMwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjArMQwwCgYDVQQKDANTQU0xGzAZBgNVBAMMEkNvbnRyYWN0IENlcnQgQ2VydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIFsO8jWd7O3MXfTY5pKVTxmIgC7X9sCo/FF+IkHuOLhC0fzRKzkg925f7wNhd2VkAwXHdA2VGZwcHBb/VQxA+ejIzAhMA4GA1UdDwEB/wQEAwIHgDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCerOke885OlhxEGyvJ0NPbt6nzz9sQGbulTxlWD217ygIgapcYQb1vEDrtSeWQGLa1eysRw+8yibThH2ZGPUIectU="
                )
            ]
        ),
        ContractSignatureCertChain=CertificateChain(
            Certificate="MIIBmDCCAQGgAwIBAgIBATAKBggqhkjOPQQDAjAzMRwwGgYDVQQKDBNDb250cmFjdCBDZXJ0IENBMRMwEQYDVQQDDApDQyBTdWIgQ0EwHhcNMjMwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjArMQwwCgYDVQQKDANDQ0ExGzAZBgNVBAMMEkNvbnRyYWN0IENlcnQgQ2VydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIFsO8jWd7O3MXfTY5pKVTxmIgC7X9sCo/FF+IkHuOLhC0fzRKzkg925f7wNhd2VkAwXHdA2VGZwcHBb/VQxA+ejIzAhMA4GA1UdDwEB/wQEAwIHgDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCerOke885OlhxEGyvJ0NPbt6nzz9sQGbulTxlWD217ygIgapcYQb1vEDrtSeWQGLa1eysRw+8yibThH2ZGPUIectU=",
            SubCertificates=[
                SubCertificate(
                    Certificate="MIIBmDCCAQGgAwIBAgIBATAKBggqhkjOPQQDAjAzMRwwGgYDVQQKDBNDb250cmFjdCBDZXJ0IENBMRMwEQYDVQQDDApDQyBSb290IENBMHgXDTIzMDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowKzEMMAoGA1UECgwDQ0NBMRswGQYDVQQDDBJDb250cmFjdCBDZXJ0IENlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASBbDvI1neztxF302OaSlU8ZiIAu1/bAqPxRfiJB7ji4QtH80Ss5IPduX+8DYXdlZAMFx3QNlRmcHBwW/1UMQPnoyMwITAOBgNVHQ8BAf8EBAMCB4AwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAnqzpHvPOTpYcRBsrydDT27ep88/bEBm7pU8ZVg9te8oCIGqXGEG9bxA67UnlkBi2tXsrEcPvMom04R9mRj1CHnLV"
                )
            ]
        ),
        ContractSignatureEncryptedPrivateKey=EncryptedPrivateKey(
            Id="ID2",
            Value="VGhpcyBpcyBhbiBleGFtcGxlIG9mIGFuIGVuY3J5cHRlZCBwcml2YXRlIGtleQ=="
        ),
        DHpublickey=EncryptedPrivateKey(
            Id="ID3",
            Value="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgWw7yNZ3s7cxd9NjmkpVPGYiALtf2wKj8UX4iQe44uELR/NErOSD3bl/vA2F3ZWQDB8d0DZUZnBwcFv9VDED5w=="
        ),
        eMAID=EncryptedPrivateKey(
            Id="ID4",
            Value="FRXYZ1234567890"
        )
    )

    # Encode the response to EXI
    exi_bytes = exi_handler.EncodeCertRes(response)
    print("Response encoded to EXI successfully")

    # Convert to base64 for demonstration
    base64_exi = base64.b64encode(exi_bytes).decode('utf-8')
    print(f"Base64 encoded EXI: {base64_exi[:50]}...")

    # Decode back to response object
    decoded_response = exi_handler.DecodeCertRes(base64_exi)
    print("Response decoded from EXI successfully")
    print(f"Decoded SessionID: {decoded_response.SessionID}")
    print(f"Decoded ResponseCode: {decoded_response.ResponseCode}")

if __name__ == "__main__":
    test_certificate_installation() 