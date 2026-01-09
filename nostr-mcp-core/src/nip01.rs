use crate::error::CoreError;

pub fn validate_time_bounds(since: Option<u64>, until: Option<u64>) -> Result<(), CoreError> {
    if let (Some(start), Some(end)) = (since, until) {
        if start > end {
            return Err(CoreError::invalid_input(
                "since must be less than or equal to until",
            ));
        }
    }
    Ok(())
}

pub fn validate_limit(limit: Option<u64>) -> Result<(), CoreError> {
    if let Some(value) = limit {
        if value == 0 {
            return Err(CoreError::invalid_input("limit must be greater than zero"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_limit, validate_time_bounds};

    #[test]
    fn validate_time_bounds_rejects_reverse_range() {
        let err = validate_time_bounds(Some(20), Some(10)).unwrap_err();
        assert!(err.to_string().contains("since must be"));
    }

    #[test]
    fn validate_time_bounds_accepts_equal_range() {
        validate_time_bounds(Some(10), Some(10)).unwrap();
    }

    #[test]
    fn validate_limit_rejects_zero() {
        let err = validate_limit(Some(0)).unwrap_err();
        assert!(err.to_string().contains("limit must be"));
    }
}
