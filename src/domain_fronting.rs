use tokio::net::TcpStream;

use crate::config::{DomainFrontingMode, FallbackConfig};
use crate::error::{Result, StealthGateError};
use crate::proxy::copy_bidirectional;

/// Определяет адрес domain fronting для fallback-соединения.
pub fn resolve_fronting_target(
  config: &FallbackConfig,
  sni: Option<&str>,
) -> Option<String> {
  match config.domain_fronting {
    DomainFrontingMode::None => None,
    DomainFrontingMode::Sni => sni.map(|host| format!("{host}:{}", config.fronting_port)),
    DomainFrontingMode::Fixed => config
      .fronting_host
      .as_ref()
      .map(|host| format!("{host}:{}", config.fronting_port)),
  }
}

/// Прозрачно проксирует TCP на upstream (domain fronting).
pub async fn forward_tcp(
  client: TcpStream,
  initial_data: &[u8],
  upstream: &str,
) -> Result<()> {
  let mut upstream_stream = TcpStream::connect(upstream)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("domain fronting к {upstream}: {err}")))?;

  upstream_stream
    .write_all_prefix(initial_data)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("запись в fronting upstream: {err}")))?;

  copy_bidirectional(client, upstream_stream).await?;
  Ok(())
}

trait WriteAllPrefix {
  async fn write_all_prefix(&mut self, data: &[u8]) -> std::io::Result<()>;
}

impl WriteAllPrefix for TcpStream {
  async fn write_all_prefix(&mut self, data: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    self.write_all(data).await
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::DomainFrontingMode;

  #[test]
  fn resolves_sni_fronting() {
    let config = FallbackConfig {
      upstream: None,
      static_html: None,
      domain_fronting: DomainFrontingMode::Sni,
      fronting_host: None,
      fronting_port: 443,
    };
    assert_eq!(
      resolve_fronting_target(&config, Some("www.cloudflare.com")),
      Some("www.cloudflare.com:443".into())
    );
  }

  #[test]
  fn resolves_fixed_fronting() {
    let config = FallbackConfig {
      upstream: None,
      static_html: None,
      domain_fronting: DomainFrontingMode::Fixed,
      fronting_host: Some("www.microsoft.com".into()),
      fronting_port: 443,
    };
    assert_eq!(
      resolve_fronting_target(&config, None),
      Some("www.microsoft.com:443".into())
    );
  }
}
