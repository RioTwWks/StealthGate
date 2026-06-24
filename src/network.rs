use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::NetworkConfig;
use crate::error::{Result, StealthGateError};

/// Подключается к backend напрямую или через SOCKS5.
pub async fn connect_backend(backend: &str, network: &NetworkConfig) -> Result<TcpStream> {
  if let Some(proxy) = &network.socks5_proxy {
    return socks5_connect(proxy, backend, network.backend_timeout_secs).await;
  }

  let stream = tokio::time::timeout(
    Duration::from_secs(network.backend_timeout_secs),
    TcpStream::connect(backend),
  )
  .await
  .map_err(|_| {
    StealthGateError::Proxy(format!("таймаут подключения к {backend}"))
  })?
  .map_err(|err| StealthGateError::Proxy(format!("подключение к {backend}: {err}")))?;

  Ok(stream)
}

async fn socks5_connect(proxy_url: &str, target: &str, timeout_secs: u64) -> Result<TcpStream> {
  let (proxy_host, proxy_port, username, password) = parse_socks5_url(proxy_url)?;
  let (target_host, target_port) = parse_host_port(target)?;

  let mut stream = tokio::time::timeout(
    Duration::from_secs(timeout_secs),
    TcpStream::connect((proxy_host.as_str(), proxy_port)),
  )
  .await
  .map_err(|_| StealthGateError::Proxy(format!("таймаут SOCKS5 {proxy_host}:{proxy_port}")))?
  .map_err(|err| StealthGateError::Proxy(format!("SOCKS5 connect: {err}")))?;

  if username.is_some() {
    stream
      .write_all(&[0x05, 0x02, 0x00, 0x02])
      .await
      .map_err(socks_err)?;
  } else {
    stream
      .write_all(&[0x05, 0x01, 0x00])
      .await
      .map_err(socks_err)?;
  }

  let mut response = [0u8; 2];
  read_exact(&mut stream, &mut response).await?;
  if response[0] != 0x05 {
    return Err(StealthGateError::Proxy("некорректный SOCKS5 greeting".into()));
  }

  if response[1] == 0x02 {
    let user = username.ok_or_else(|| StealthGateError::Proxy("SOCKS5 требует логин".into()))?;
    let pass = password.unwrap_or_default();
    let mut auth = vec![0x01, user.len() as u8];
    auth.extend_from_slice(user.as_bytes());
    auth.push(pass.len() as u8);
    auth.extend_from_slice(pass.as_bytes());
    stream.write_all(&auth).await.map_err(socks_err)?;
    let mut auth_resp = [0u8; 2];
    read_exact(&mut stream, &mut auth_resp).await?;
    if auth_resp[1] != 0x00 {
      return Err(StealthGateError::Proxy("SOCKS5 auth failed".into()));
    }
  } else if response[1] != 0x00 {
    return Err(StealthGateError::Proxy(format!(
      "SOCKS5 method rejected: {}",
      response[1]
    )));
  }

  let mut request = vec![0x05, 0x01, 0x00, 0x03, target_host.len() as u8];
  request.extend_from_slice(target_host.as_bytes());
  request.push((target_port >> 8) as u8);
  request.push((target_port & 0xff) as u8);
  stream.write_all(&request).await.map_err(socks_err)?;

  let mut header = [0u8; 4];
  read_exact(&mut stream, &mut header).await?;
  if header[1] != 0x00 {
    return Err(StealthGateError::Proxy(format!(
      "SOCKS5 CONNECT failed: {}",
      header[1]
    )));
  }

  match header[3] {
    0x01 => {
      let mut rest = [0u8; 6];
      read_exact(&mut stream, &mut rest).await?;
    }
    0x03 => {
      let mut len = [0u8; 1];
      read_exact(&mut stream, &mut len).await?;
      let mut rest = vec![0u8; len[0] as usize + 2];
      read_exact(&mut stream, &mut rest).await?;
    }
    0x04 => {
      let mut rest = [0u8; 18];
      read_exact(&mut stream, &mut rest).await?;
    }
    other => {
      return Err(StealthGateError::Proxy(format!(
        "неподдерживаемый SOCKS5 ATYP: {other}"
      )));
    }
  }

  Ok(stream)
}

fn parse_socks5_url(url: &str) -> Result<(String, u16, Option<String>, Option<String>)> {
  let stripped = url
    .strip_prefix("socks5://")
    .ok_or_else(|| StealthGateError::Config("SOCKS5 URL должен начинаться с socks5://".into()))?;

  let (auth, host_port) = match stripped.rsplit_once('@') {
    Some((auth, host_port)) if stripped.contains('@') && !host_port.contains('@') => {
      (Some(auth), host_port)
    }
    _ => (None, stripped),
  };

  let (username, password) = if let Some(auth) = auth {
    let (user, pass) = auth.split_once(':').ok_or_else(|| {
      StealthGateError::Config("SOCKS5 auth должен быть user:pass@host:port".into())
    })?;
    (Some(user.to_string()), Some(pass.to_string()))
  } else {
    (None, None)
  };

  let (host, port) = parse_host_port(host_port)?;
  Ok((host, port, username, password))
}

fn parse_host_port(value: &str) -> Result<(String, u16)> {
  let (host, port) = value
    .rsplit_once(':')
    .ok_or_else(|| StealthGateError::Config(format!("некорректный host:port: {value}")))?;
  let port = port
    .parse()
    .map_err(|err| StealthGateError::Config(format!("некорректный порт {port}: {err}")))?;
  Ok((host.to_string(), port))
}

async fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<()> {
  use tokio::io::AsyncReadExt;
  stream
    .read_exact(buf)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("SOCKS5 read: {err}")))?;
  Ok(())
}

fn socks_err(err: std::io::Error) -> StealthGateError {
  StealthGateError::Proxy(format!("SOCKS5 write: {err}"))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_socks5_url() {
    let (host, port, user, pass) =
      parse_socks5_url("socks5://user:pass@127.0.0.1:9050").expect("parse");
    assert_eq!(host, "127.0.0.1");
    assert_eq!(port, 9050);
    assert_eq!(user.as_deref(), Some("user"));
    assert_eq!(pass.as_deref(), Some("pass"));
  }
}
