use anyhow::{anyhow, Result};

// protocol constants
pub const REQUIRED_SESSION_ID_LEN: usize = 32;
pub const RESTLS_HANDSHAKE_HMAC_LEN: usize = 16;
pub const RESTLS_APPDATA_HMAC_LEN: usize = 8;
pub const RESTLS_APPDATA_LEN_OFFSET: usize = RESTLS_APPDATA_HMAC_LEN;
pub const RESTLS_MASK_LEN: usize = 4;
pub const RESTLS_APPDATA_OFFSET: usize = RESTLS_APPDATA_HMAC_LEN + RESTLS_MASK_LEN;
pub const TLS_RECORD_HEADER_LEN: usize = 5;

// record type
pub const RECORD_HANDSHAKE: u8 = 0x16;
pub const RECORD_APPLICATION_DATA: u8 = 0x17;
pub const RECORD_CCS: u8 = 0x14;
pub const RECORD_ALERT: u8 = 0x15;

// extension type
// enum {
//     server_name(0),                             /* RFC 6066 */
//     max_fragment_length(1),                     /* RFC 6066 */
//     status_request(5),                          /* RFC 6066 */
//     supported_groups(10),                       /* RFC 8422, 7919 */
//     signature_algorithms(13),                   /* RFC 8446 */
//     use_srtp(14),                               /* RFC 5764 */
//     heartbeat(15),                              /* RFC 6520 */
//     application_layer_protocol_negotiation(16), /* RFC 7301 */
//     signed_certificate_timestamp(18),           /* RFC 6962 */
//     client_certificate_type(19),                /* RFC 7250 */
//     server_certificate_type(20),                /* RFC 7250 */
//     padding(21),                                /* RFC 7685 */
//     pre_shared_key(41),                         /* RFC 8446 */
//     early_data(42),                             /* RFC 8446 */
//     supported_versions(43),                     /* RFC 8446 */
//     cookie(44),                                 /* RFC 8446 */
//     psk_key_exchange_modes(45),                 /* RFC 8446 */
//     certificate_authorities(47),                /* RFC 8446 */
//     oid_filters(48),                            /* RFC 8446 */
//     post_handshake_auth(49),                    /* RFC 8446 */
//     signature_algorithms_cert(50),              /* RFC 8446 */
//     key_share(51),                              /* RFC 8446 */
//     (65535)
// } ExtensionType;
pub const EXTENSION_SESSION_TICKET: u16 = 0x0023;
pub const EXTENSION_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const EXTENSION_PRE_SHARED_KEY: u16 = 0x0029;
pub const EXTENSION_KEY_SHARE: u16 = 0x0033;

// handshake type:
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 01;
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 02;
pub const HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE: u8 = 0x10;
pub const HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE: u8 = 0x0c;
pub const _HANDSHAKE_TYPE_SERVER_HELLO_DONE: u8 = 0x0e;

pub const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

pub const TO_CLIENT_MAGIC: &'static [u8] = "server-to-client".as_bytes();
pub const TO_SERVER_MAGIC: &'static [u8] = "client-to-server".as_bytes();

pub const BUF_SIZE: usize = 0x3000;

pub const CCS_RECORD: &'static [u8] = &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

pub const CLIENT_AUTH_LAYOUT3: &'static [usize] = &[0, 11, 22, 32];
pub const CLIENT_AUTH_LAYOUT4: &'static [usize] = &[0, 8, 16, 24, 32];
pub const CLIENT_AUTH_SESSION_TICKET_OFFSET: usize = CLIENT_AUTH_LAYOUT4[3];
pub const CLIENT_AUTH_SESSION_TICKET_LEN: usize =
    CLIENT_AUTH_LAYOUT4[4] - CLIENT_AUTH_SESSION_TICKET_OFFSET;

pub const CURVE_P256: usize = 23;
pub const CURVE_P384: usize = 24;
pub const X25519: usize = 29;

pub fn curve_id_to_index(curve_id: usize) -> Result<usize> {
    match curve_id {
        X25519 => Ok(0),
        CURVE_P256 => Ok(1),
        CURVE_P384 => Ok(2),
        _ => Err(anyhow!("reject: unsupported curve id")),
    }
}

pub const TLS12_GCM_CIPHER_SUITES: &[u16] = &[0xc02f, 0xc02b, 0xc030, 0xc02c];
