//! Durations and timestamps as people write them: `15m`, `12h`, `1h 30m`, `2023-01-02T03:04:05Z`.
//!
//! Replaces the `humantime` crate (unmaintained, RUSTSEC-2026-0542; DR-4) with the same accepted
//! input and the same printed output for everything the server reads and prints: the config's
//! durations, `invite create --expires` and the dates in `user list` and friends.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NANOS_PER_SEC: u128 = 1_000_000_000;
const MINUTE: u64 = 60;
const HOUR: u64 = 3600;
const DAY: u64 = 86_400;
const WEEK: u64 = 7 * DAY;
/// 30.44 days, as humantime defined it.
const MONTH: u64 = 2_630_016;
/// 365.25 days.
const YEAR: u64 = 31_557_600;

/// Why a duration did not parse. Offsets are byte offsets into the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DurationError {
    /// Something that is neither a digit, a letter, a dot nor whitespace.
    InvalidCharacter(usize),
    /// A unit or other text where a number has to come.
    NumberExpected(usize),
    /// A number without a unit (`unit` empty) or with one we do not know.
    UnknownUnit {
        /// The unit as written.
        unit: String,
        /// The number in front of it.
        value: u64,
    },
    /// Too large, or finer than a nanosecond.
    NumberOverflow,
    /// Empty or only whitespace.
    Empty,
}

impl std::error::Error for DurationError {}

impl fmt::Display for DurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCharacter(offset) => write!(f, "invalid character at {offset}"),
            Self::NumberExpected(offset) => write!(f, "expected number at {offset}"),
            Self::UnknownUnit { unit, value } if unit.is_empty() => {
                write!(f, "time unit needed, for example {value}sec or {value}ms")
            }
            Self::UnknownUnit { unit, .. } => write!(
                f,
                "unknown time unit {unit:?}, supported units: ns, us/µs, ms, sec, min, hours, \
                 days, weeks, months, years (and few variations)"
            ),
            Self::NumberOverflow => f.write_str(
                "number is too large or cannot be represented without a lack of precision \
                 (values below 1ns are not supported)",
            ),
            Self::Empty => f.write_str("value was empty"),
        }
    }
}

/// One unit's length in nanoseconds.
fn unit_nanos(unit: &str) -> Option<u128> {
    let secs = |s: u64| Some(u128::from(s) * NANOS_PER_SEC);
    match unit {
        "nanos" | "nsec" | "ns" => Some(1),
        "usec" | "us" | "µs" => Some(1_000),
        "millis" | "msec" | "ms" => Some(1_000_000),
        "seconds" | "second" | "secs" | "sec" | "s" => secs(1),
        "minutes" | "minute" | "min" | "mins" | "m" => secs(MINUTE),
        "hours" | "hour" | "hr" | "hrs" | "h" => secs(HOUR),
        "days" | "day" | "d" => secs(DAY),
        "weeks" | "week" | "wk" | "wks" | "w" => secs(WEEK),
        "months" | "month" | "M" => secs(MONTH),
        "years" | "year" | "yr" | "yrs" | "y" => secs(YEAR),
        _ => None,
    }
}

const fn is_unit_char(c: char) -> bool {
    c.is_ascii_alphabetic() || c == 'µ'
}

/// Parses a sum of spans like `1h 30m`, `2days`, `100ms` or `4.5s`; a bare `0` is zero.
pub(crate) fn parse_duration(text: &str) -> Result<Duration, DurationError> {
    if text == "0" {
        return Ok(Duration::ZERO);
    }
    let mut chars = text.char_indices().peekable();
    let mut total: u128 = 0;
    let mut spans = 0_usize;
    loop {
        // Whitespace, then a number.
        while chars.next_if(|&(_, c)| c.is_whitespace()).is_some() {}
        let Some(&(at, first)) = chars.peek() else {
            return if spans == 0 {
                Err(DurationError::Empty)
            } else {
                to_duration(total)
            };
        };
        if !first.is_ascii_digit() {
            return Err(DurationError::NumberExpected(at));
        }
        let mut whole: u64 = 0;
        let mut fraction: Option<(u128, u128)> = None;
        while let Some(&(at, c)) = chars.peek() {
            if let Some(digit) = c.to_digit(10) {
                whole = whole
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(u64::from(digit)))
                    .ok_or(DurationError::NumberOverflow)?;
            } else if c == '.' {
                chars.next();
                fraction = Some(parse_fraction(&mut chars, at)?);
                break;
            } else if is_unit_char(c) {
                break;
            } else if !c.is_whitespace() {
                return Err(DurationError::InvalidCharacter(at));
            }
            chars.next();
        }
        // The unit: letters up to whitespace, a digit or the end.
        let start = chars.peek().map_or(text.len(), |&(at, _)| at);
        let mut end = start;
        while let Some(&(at, c)) = chars.peek() {
            if is_unit_char(c) {
                end = at + c.len_utf8();
                chars.next();
            } else if c.is_whitespace() || c.is_ascii_digit() {
                break;
            } else {
                return Err(DurationError::InvalidCharacter(at));
            }
        }
        let unit = &text[start..end];
        let nanos = unit_nanos(unit).ok_or_else(|| DurationError::UnknownUnit {
            unit: unit.to_owned(),
            value: whole,
        })?;
        total = u128::from(whole)
            .checked_mul(nanos)
            .and_then(|n| total.checked_add(n))
            .ok_or(DurationError::NumberOverflow)?;
        if let Some((numerator, denominator)) = fraction {
            let scaled = numerator
                .checked_mul(nanos)
                .ok_or(DurationError::NumberOverflow)?;
            if scaled % denominator != 0 {
                return Err(DurationError::NumberOverflow);
            }
            total = total
                .checked_add(scaled / denominator)
                .ok_or(DurationError::NumberOverflow)?;
        }
        spans += 1;
    }
}

/// The digits after a decimal dot at byte `dot`, as numerator and denominator.
fn parse_fraction(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    dot: usize,
) -> Result<(u128, u128), DurationError> {
    let mut numerator: u128 = 0;
    let mut denominator: u128 = 1;
    let mut last = dot;
    while let Some(&(at, c)) = chars.peek() {
        if let Some(digit) = c.to_digit(10) {
            numerator = numerator * 10 + u128::from(digit);
            denominator *= 10;
            // More than 1ns precision can never come out even.
            if denominator > 10_u128.pow(30) {
                return Err(DurationError::NumberOverflow);
            }
        } else if is_unit_char(c) {
            break;
        } else if !c.is_whitespace() {
            return Err(DurationError::InvalidCharacter(at));
        }
        last = at + c.len_utf8();
        chars.next();
    }
    if denominator == 1 {
        // `1.` or `1.s`: no digits after the dot.
        return Err(DurationError::InvalidCharacter(last));
    }
    Ok((numerator, denominator))
}

fn to_duration(nanos: u128) -> Result<Duration, DurationError> {
    let secs = u64::try_from(nanos / NANOS_PER_SEC).map_err(|_| DurationError::NumberOverflow)?;
    let subsec = u32::try_from(nanos % NANOS_PER_SEC).map_err(|_| DurationError::NumberOverflow)?;
    Ok(Duration::new(secs, subsec))
}

/// A duration printed the way [`format_duration`] does.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FormattedDuration(Duration);

/// Prints a duration as `2days 3h 5m`, `1year 2months`, `150ms` or `0s`; the result parses back.
pub(crate) const fn format_duration(duration: Duration) -> FormattedDuration {
    FormattedDuration(duration)
}

impl fmt::Display for FormattedDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_secs();
        let nanos = u64::from(self.0.subsec_nanos());
        if secs == 0 && nanos == 0 {
            return f.write_str("0s");
        }
        let in_year = secs % YEAR;
        let in_month = in_year % MONTH;
        let in_day = in_month % DAY;
        let parts: [(u64, &str, bool); 9] = [
            (secs / YEAR, "year", true),
            (in_year / MONTH, "month", true),
            (in_month / DAY, "day", true),
            (in_day / HOUR, "h", false),
            (in_day % HOUR / MINUTE, "m", false),
            (in_day % MINUTE, "s", false),
            (nanos / 1_000_000, "ms", false),
            (nanos / 1_000 % 1_000, "us", false),
            (nanos % 1_000, "ns", false),
        ];
        let mut started = false;
        for (value, name, plural) in parts {
            if value == 0 {
                continue;
            }
            if started {
                f.write_str(" ")?;
            }
            write!(f, "{value}{name}")?;
            if plural && value > 1 {
                f.write_str("s")?;
            }
            started = true;
        }
        Ok(())
    }
}

/// A point in time printed as RFC 3339 in UTC, to the second: `2026-11-18T13:52:13Z`.
/// Times before 1970 print as the epoch.
pub(crate) fn format_rfc3339_seconds(at: SystemTime) -> String {
    let secs = at
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let (year, month, day) = civil_from_days(secs / DAY);
    let in_day = secs % DAY;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        in_day / HOUR,
        in_day % HOUR / MINUTE,
        in_day % MINUTE
    )
}

/// The proleptic Gregorian date of a day count since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`, for non-negative days).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> Duration {
        parse_duration(text).unwrap_or_else(|error| unreachable!("{text:?}: {error}"))
    }

    #[test]
    fn parses_what_the_config_and_cli_document() {
        assert_eq!(ok("0"), Duration::ZERO);
        assert_eq!(ok("0s"), Duration::ZERO);
        assert_eq!(ok("100ms"), Duration::from_millis(100));
        assert_eq!(ok("30s"), Duration::from_secs(30));
        assert_eq!(ok("60s"), Duration::from_secs(60));
        assert_eq!(ok("10m"), Duration::from_mins(10));
        assert_eq!(ok("15m"), Duration::from_mins(15));
        assert_eq!(ok("1h"), Duration::from_hours(1));
        assert_eq!(ok("12h"), Duration::from_hours(12));
        assert_eq!(ok("24h"), Duration::from_secs(DAY));
        assert_eq!(ok("1d"), Duration::from_secs(DAY));
        assert_eq!(ok("2d"), Duration::from_secs(2 * DAY));
        assert_eq!(ok("7d"), Duration::from_secs(WEEK));
        assert_eq!(ok("1h 30m"), Duration::from_mins(90));
        assert_eq!(ok("1h30m"), Duration::from_mins(90));
        assert_eq!(ok("  2 hours 37min "), Duration::from_mins(157));
        assert_eq!(ok("2days"), Duration::from_secs(2 * DAY));
        assert_eq!(ok("1w"), Duration::from_secs(WEEK));
        assert_eq!(ok("1M"), Duration::from_secs(MONTH));
        assert_eq!(ok("1y"), Duration::from_secs(YEAR));
        assert_eq!(ok("5us"), Duration::from_micros(5));
        assert_eq!(ok("5µs"), Duration::from_micros(5));
        assert_eq!(ok("7ns"), Duration::from_nanos(7));
        assert_eq!(ok("4.2s"), Duration::from_millis(4200));
        assert_eq!(ok("1.5h"), Duration::from_mins(90));
        assert_eq!(ok("0.5ms"), Duration::from_micros(500));
    }

    #[test]
    fn refuses_like_humantime() {
        let error = |text: &str| parse_duration(text).map_err(|e| e.to_string()).unwrap_err();
        assert_eq!(error(""), "value was empty");
        assert_eq!(error("   "), "value was empty");
        assert_eq!(error("soon"), "expected number at 0");
        assert_eq!(error("forever"), "expected number at 0");
        assert_eq!(error("15"), "time unit needed, for example 15sec or 15ms");
        assert!(error("3parsecs").starts_with("unknown time unit \"parsecs\""));
        assert_eq!(error("1h, 2m"), "invalid character at 2");
        assert_eq!(error("1.s"), "invalid character at 1");
        assert_eq!(error("1. s"), "invalid character at 3");
        assert!(error("0.5ns").starts_with("number is too large"));
        assert!(error("99999999999999999999s").starts_with("number is too large"));
        assert!(error("999999999999years").starts_with("number is too large"));
    }

    #[test]
    fn formats_like_humantime() {
        let text = |d: Duration| format_duration(d).to_string();
        assert_eq!(text(Duration::ZERO), "0s");
        assert_eq!(text(Duration::from_millis(100)), "100ms");
        assert_eq!(text(Duration::from_secs(30)), "30s");
        assert_eq!(text(Duration::from_mins(157)), "2h 37m");
        assert_eq!(text(Duration::from_secs(DAY)), "1day");
        assert_eq!(text(Duration::from_secs(2 * DAY)), "2days");
        assert_eq!(text(Duration::from_secs(WEEK)), "7days");
        assert_eq!(text(Duration::from_secs(YEAR + 2 * MONTH)), "1year 2months");
        assert_eq!(
            text(Duration::new(DAY + 3661, 1_002_003)),
            "1day 1h 1m 1s 1ms 2us 3ns"
        );
    }

    #[test]
    fn formatted_durations_parse_back() {
        for d in [
            Duration::from_millis(1),
            Duration::from_secs(59),
            Duration::from_secs(3 * DAY + 7),
            Duration::new(YEAR * 3 + MONTH + 5, 999_999_999),
        ] {
            assert_eq!(ok(&format_duration(d).to_string()), d);
        }
    }

    #[test]
    fn formats_utc_timestamps() {
        let at = |secs: u64| format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(secs));
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(at(1_672_628_645), "2023-01-02T03:04:05Z");
        assert_eq!(at(1_795_009_933), "2026-11-18T13:52:13Z");
        assert_eq!(at(4_107_542_399), "2100-02-28T23:59:59Z");
        assert_eq!(
            format_rfc3339_seconds(UNIX_EPOCH - Duration::from_secs(5)),
            at(0)
        );
        let fraction = UNIX_EPOCH + Duration::from_millis(1_672_628_645_999);
        assert_eq!(format_rfc3339_seconds(fraction), "2023-01-02T03:04:05Z");
    }
}
