use std::net::IpAddr;

pub fn hostname_from_prefix(bytes: &[u8]) -> Option<String> {
    tls_sni(bytes).or_else(|| http_host(bytes))
}

fn tls_sni(bytes: &[u8]) -> Option<String> {
    let mut offset = 0usize;
    let mut handshake = Vec::new();

    while offset.checked_add(5)? <= bytes.len() {
        let content_type = bytes[offset];
        let record_len = u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]) as usize;
        let payload_start = offset + 5;
        let payload_end = payload_start.checked_add(record_len)?;
        if payload_end > bytes.len() {
            break;
        }

        if content_type == 0x16 {
            handshake.extend_from_slice(&bytes[payload_start..payload_end]);
            if handshake.len() >= 4 {
                let message_len = ((handshake[1] as usize) << 16)
                    | ((handshake[2] as usize) << 8)
                    | handshake[3] as usize;
                if handshake[0] != 0x01 {
                    return None;
                }
                if handshake.len() >= message_len + 4 {
                    return sni_from_client_hello(&handshake[4..message_len + 4]);
                }
            }
        } else if handshake.is_empty() {
            return None;
        }

        offset = payload_end;
    }

    None
}

fn sni_from_client_hello(body: &[u8]) -> Option<String> {
    let mut cursor = 0usize;
    take(body, &mut cursor, 2 + 32)?;

    let session_len = *take(body, &mut cursor, 1)?.first()? as usize;
    take(body, &mut cursor, session_len)?;

    let cipher_len = read_u16(body, &mut cursor)? as usize;
    take(body, &mut cursor, cipher_len)?;

    let compression_len = *take(body, &mut cursor, 1)?.first()? as usize;
    take(body, &mut cursor, compression_len)?;

    let extensions_len = read_u16(body, &mut cursor)? as usize;
    let extensions = take(body, &mut cursor, extensions_len)?;
    let mut ext_cursor = 0usize;

    while ext_cursor < extensions.len() {
        let extension_type = read_u16(extensions, &mut ext_cursor)?;
        let extension_len = read_u16(extensions, &mut ext_cursor)? as usize;
        let extension = take(extensions, &mut ext_cursor, extension_len)?;
        if extension_type != 0x0000 {
            continue;
        }

        let mut name_cursor = 0usize;
        let list_len = read_u16(extension, &mut name_cursor)? as usize;
        let names = take(extension, &mut name_cursor, list_len)?;
        let mut list_cursor = 0usize;
        while list_cursor < names.len() {
            let name_type = *take(names, &mut list_cursor, 1)?.first()?;
            let name_len = read_u16(names, &mut list_cursor)? as usize;
            let name = take(names, &mut list_cursor, name_len)?;
            if name_type == 0 {
                return normalize_hostname(name);
            }
        }
    }

    None
}

fn http_host(bytes: &[u8]) -> Option<String> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap_or(bytes.len().min(16 * 1024));
    let header = std::str::from_utf8(&bytes[..header_end]).ok()?;
    let first_line = header.lines().next()?;
    if !first_line.contains("HTTP/") && !first_line.starts_with("CONNECT ") {
        return None;
    }

    for line in header.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
            return normalize_host_value(value.trim());
        }
    }

    if let Some(authority) = first_line
        .strip_prefix("CONNECT ")
        .and_then(|rest| rest.split_whitespace().next())
    {
        return normalize_host_value(authority);
    }

    None
}

fn normalize_host_value(value: &str) -> Option<String> {
    let host = if let Some(stripped) = value.strip_prefix('[') {
        stripped.split_once(']')?.0
    } else if value.matches(':').count() == 1 {
        value.split_once(':').map_or(value, |(host, _)| host)
    } else {
        value
    };
    normalize_hostname(host.as_bytes())
}

fn normalize_hostname(bytes: &[u8]) -> Option<String> {
    let host = std::str::from_utf8(bytes).ok()?.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 || host.parse::<IpAddr>().is_ok() {
        return None;
    }
    if !host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Option<u16> {
    let value = take(bytes, cursor, 2)?;
    Some(u16::from_be_bytes([value[0], value[1]]))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = cursor.checked_add(len)?;
    let value = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::hostname_from_prefix;

    #[test]
    fn extracts_http_host() {
        let request = b"GET /v1/models HTTP/1.1\r\nHost: API.OpenAI.com:443\r\n\r\n";
        assert_eq!(
            hostname_from_prefix(request).as_deref(),
            Some("api.openai.com")
        );
    }

    #[test]
    fn extracts_tls_sni() {
        let hello = client_hello("api.openai.com");
        assert_eq!(
            hostname_from_prefix(&hello).as_deref(),
            Some("api.openai.com")
        );
    }

    #[test]
    fn ignores_ip_host_header() {
        let request = b"GET / HTTP/1.1\r\nHost: 203.0.113.7\r\n\r\n";
        assert_eq!(hostname_from_prefix(request), None);
    }

    fn client_hello(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        server_name.push(0);
        server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
        server_name.extend_from_slice(host);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&server_name);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![
            0x01,
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
