"""Verify HeadSpin capture-agent cert layout works as a mitm12 confdir."""

from cryptography.hazmat.primitives import serialization

from mitmproxy import certs


def test_capture_agent_confdir_layout(tmp_path):
    """mitm_certs.create_cert_dir writes key+cert PEM as mitmproxy-ca.pem."""
    key, ca = certs.create_ca(organization="mitmproxy", cn="mitmproxy", key_size=2048)
    pem_path = tmp_path / "mitmproxy-ca.pem"
    pem_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        + ca.public_bytes(serialization.Encoding.PEM)
    )

    store = certs.CertStore.from_store(tmp_path, "mitmproxy", 2048)
    assert store.default_ca.cn == "mitmproxy"
    assert (tmp_path / "mitmproxy-dhparam.pem").exists()
