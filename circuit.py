import os
import M2Crypto
from tls_client import handle_server_hello, SECP256R1_A, SECP256R1_G, SECP256R1_P, hmac_sha256, derive_secret, sha256, multiply_num_on_ec_point, num_to_bytes, \
    load_tls_and_decrypt, HANDSHAKE, handle_server_cert, load, handle_cert_verify, handle_finished, APPLICATION_DATA, ALERT


# w: private witness, x: public data
def circuit(w, x):
    our_ecdh_privkey = int(load('client_privkey', w)[0])
    print(our_ecdh_privkey)
    our_ecdh_pubkey_x, our_ecdh_pubkey_y = (
        multiply_num_on_ec_point(our_ecdh_privkey, SECP256R1_G[0], SECP256R1_G[1], SECP256R1_A, SECP256R1_P)
    )
    client_hello = load('client_hello', w)
    server_hello = load('server_hello', w)
    server_random, session_id, server_ecdh_pubkey_x, server_ecdh_pubkey_y = handle_server_hello(server_hello)
    our_secret_point_x = multiply_num_on_ec_point(our_ecdh_privkey, server_ecdh_pubkey_x, server_ecdh_pubkey_y,
                                                SECP256R1_A, SECP256R1_P)[0]
    our_secret = num_to_bytes(our_secret_point_x, 32)

    early_secret = hmac_sha256(key=b"", data=b"\x00" * 32)
    preextractsec = derive_secret(b"derived", key=early_secret, data=sha256(b""), hash_len=32)
    handshake_secret = hmac_sha256(key=preextractsec, data=our_secret)
    hello_hash = sha256(client_hello + server_hello)
    server_hs_secret = derive_secret(b"s hs traffic", key=handshake_secret, data=hello_hash, hash_len=32)
    server_write_key = derive_secret(b"key", key=server_hs_secret, data=b"", hash_len=16)
    server_write_iv = derive_secret(b"iv", key=server_hs_secret, data=b"", hash_len=12)
    server_finished_key = derive_secret(b"finished", key=server_hs_secret, data=b"", hash_len=32)
    client_hs_secret = derive_secret(b"c hs traffic", key=handshake_secret, data=hello_hash, hash_len=32)
    client_write_key = derive_secret(b"key", key=client_hs_secret, data=b"", hash_len=16)
    client_write_iv = derive_secret(b"iv", key=client_hs_secret, data=b"", hash_len=12)
    client_finished_key = derive_secret(b"finished", key=client_hs_secret, data=b"", hash_len=32)

    client_seq_num = 0
    server_seq_num = 0

    print("Loading encrypted extensions")
    rec_type, encrypted_extensions = load_tls_and_decrypt(w, server_write_key, server_write_iv, server_seq_num)
    assert rec_type == HANDSHAKE
    server_seq_num += 1

    print("Loading server certificates")

    rec_type, server_cert = load_tls_and_decrypt(w, server_write_key, server_write_iv, server_seq_num)
    assert rec_type == HANDSHAKE
    server_seq_num += 1

    certs = handle_server_cert(server_cert)
    print(f"    Got {len(certs)} certs")

    bio = M2Crypto.BIO.MemoryBuffer(certs[0])
    cert = M2Crypto.X509.load_cert_bio(bio, M2Crypto.X509.FORMAT_DER)
    cert_pubkey = cert.get_pubkey().as_der()

    issuer_cert = M2Crypto.X509.load_cert('digicert.der', M2Crypto.X509.FORMAT_DER)
    issuer_pubkey = issuer_cert.get_pubkey()

    if cert.verify(issuer_pubkey):
        print('cert is issued by digicert')
    else:
        print('cert is not issued by digicert')
        exit(1)

    print("Receiving server verify certificate")
    rec_type, cert_verify = load_tls_and_decrypt(w, server_write_key, server_write_iv, server_seq_num)
    assert rec_type == HANDSHAKE
    server_seq_num += 1

    msgs_so_far = client_hello + server_hello + encrypted_extensions + server_cert
    cert_ok = handle_cert_verify(cert_verify, cert_pubkey, msgs_so_far)
    if cert_ok:
        print('Certificate verifying OK, server owns the corresponding private key')
    else:
        print("    Certificate verifying failed")
        exit(1)

    print("Receiving server finished")
    rec_type, finished = load_tls_and_decrypt(w, server_write_key, server_write_iv, server_seq_num)
    assert rec_type == HANDSHAKE
    server_seq_num += 1

    msgs_so_far = msgs_so_far + cert_verify
    srv_finish_ok = handle_finished(finished, server_finished_key, msgs_so_far)
    if srv_finish_ok:
        print("    Server sent valid finish handshake msg")
    else:
        print("    Warning: Server sent wrong handshake finished msg")
    
    msgs_so_far = msgs_so_far + finished
    msgs_so_far_hash = sha256(msgs_so_far)
    premaster_secret = derive_secret(b"derived", data=sha256(b""), key=handshake_secret, hash_len=32)
    master_secret = hmac_sha256(key=premaster_secret, data=b"\x00" * 32)
    server_secret = derive_secret(b"s ap traffic", data=msgs_so_far_hash, key=master_secret, hash_len=32)
    server_write_key = derive_secret(b"key", data=b"", key=server_secret, hash_len=16)
    server_write_iv = derive_secret(b"iv", data=b"", key=server_secret, hash_len=12)
    client_secret = derive_secret(b"c ap traffic", data=msgs_so_far_hash, key=master_secret, hash_len=32)
    client_write_key = derive_secret(b"key", data=b"", key=client_secret, hash_len=16)
    client_write_iv = derive_secret(b"iv", data=b"", key=client_secret, hash_len=12)

    # reset sequence numbers
    client_seq_num = 0
    server_seq_num = 0

    data = b''
    while True:
        rec_type, msg = load_tls_and_decrypt(w, server_write_key, server_write_iv, server_seq_num, prefix = 'app_')
        server_seq_num += 1

        if rec_type == APPLICATION_DATA:
            data+=msg
        elif rec_type == HANDSHAKE:
            NEW_SESSION_TICKET = 4
            if msg[0] == NEW_SESSION_TICKET:
                print(f"New session ticket: {msg.hex()}")
        elif rec_type == ALERT:
            alert_level, alert_description = msg

            print(f"Got alert level: {alert_level}, description: {alert_description}")
            CLOSE_NOTIFY = 0
            if alert_description == CLOSE_NOTIFY:
                print("Server sent close_notify, no waiting for more data")
                break
        else:
            print("Got msg with unknown rec_type", rec_type)
    
    print(data)
    # check x in data



if __name__ == '__main__':
    circuit('witness', (1633835497610, 'AAPL', '142.90'))