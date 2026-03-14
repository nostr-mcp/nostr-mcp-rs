use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::Nip46Error;
use crate::message::Nip46RequestId;
use crate::permission::Nip46Method;

#[derive(Debug, Clone)]
pub struct Nip46PendingRequest {
    method: Nip46Method,
    request_id: Nip46RequestId,
    expires_at_unix_seconds: u64,
    consumed: Arc<AtomicBool>,
}

impl Nip46PendingRequest {
    pub fn new(
        method: Nip46Method,
        request_id: Nip46RequestId,
        created_at_unix_seconds: u64,
        timeout_secs: u64,
    ) -> Result<Self, Nip46Error> {
        if timeout_secs == 0 {
            return Err(Nip46Error::invalid_timeout_seconds(timeout_secs));
        }

        let expires_at_unix_seconds = created_at_unix_seconds
            .checked_add(timeout_secs)
            .ok_or_else(|| Nip46Error::invalid_timeout_seconds(timeout_secs))?;

        Ok(Self {
            method,
            request_id,
            expires_at_unix_seconds,
            consumed: Arc::new(AtomicBool::new(false)),
        })
    }

    pub const fn method(&self) -> Nip46Method {
        self.method
    }

    pub fn request_id(&self) -> &Nip46RequestId {
        &self.request_id
    }

    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    pub fn ensure_active(&self, now_unix_seconds: u64) -> Result<(), Nip46Error> {
        self.ensure_not_consumed()?;
        if now_unix_seconds > self.expires_at_unix_seconds {
            return Err(Nip46Error::request_timed_out(
                self.method,
                self.request_id.clone(),
            ));
        }
        Ok(())
    }

    pub fn accept_response(
        &self,
        now_unix_seconds: u64,
        response_id: &Nip46RequestId,
    ) -> Result<(), Nip46Error> {
        self.ensure_active(now_unix_seconds)?;
        if response_id != &self.request_id {
            return Err(Nip46Error::UnexpectedResponseId {
                expected: self.request_id.to_string(),
                received: response_id.to_string(),
            });
        }

        if self.consumed.swap(true, Ordering::AcqRel) {
            return Err(Nip46Error::request_replayed(
                self.method,
                self.request_id.clone(),
            ));
        }

        Ok(())
    }

    fn ensure_not_consumed(&self) -> Result<(), Nip46Error> {
        if self.consumed.load(Ordering::Acquire) {
            return Err(Nip46Error::request_replayed(
                self.method,
                self.request_id.clone(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::message::Nip46RequestId;
    use crate::permission::Nip46Method;

    use super::Nip46PendingRequest;

    #[test]
    fn pending_request_accepts_matching_response_before_timeout() {
        let pending = Nip46PendingRequest::new(
            Nip46Method::GetPublicKey,
            Nip46RequestId::new("3047714677").unwrap(),
            1_700_000_000,
            30,
        )
        .unwrap();

        assert_eq!(pending.method(), Nip46Method::GetPublicKey);
        assert_eq!(pending.request_id().as_str(), "3047714677");
        assert_eq!(pending.expires_at_unix_seconds(), 1_700_000_030);
        pending
            .accept_response(1_700_000_010, &Nip46RequestId::new("3047714677").unwrap())
            .unwrap();
    }

    #[test]
    fn pending_request_rejects_zero_timeout() {
        let err = Nip46PendingRequest::new(
            Nip46Method::GetPublicKey,
            Nip46RequestId::new("3047714677").unwrap(),
            1_700_000_000,
            0,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid timeout seconds: expected a positive bounded timeout, received `0`"
        );
    }

    #[test]
    fn pending_request_rejects_timeout() {
        let pending = Nip46PendingRequest::new(
            Nip46Method::SwitchRelays,
            Nip46RequestId::new("3047714678").unwrap(),
            1_700_000_000,
            5,
        )
        .unwrap();

        let err = pending
            .accept_response(1_700_000_006, &Nip46RequestId::new("3047714678").unwrap())
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "request timed out for `switch_relays` with id `3047714678`"
        );
    }

    #[test]
    fn pending_request_rejects_replay_after_success() {
        let pending = Nip46PendingRequest::new(
            Nip46Method::GetPublicKey,
            Nip46RequestId::new("3047714679").unwrap(),
            1_700_000_000,
            30,
        )
        .unwrap();
        let replay = pending.clone();

        pending
            .accept_response(1_700_000_001, &Nip46RequestId::new("3047714679").unwrap())
            .unwrap();
        let err = replay
            .accept_response(1_700_000_002, &Nip46RequestId::new("3047714679").unwrap())
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "replayed response for `get_public_key` with id `3047714679`"
        );
    }
}
