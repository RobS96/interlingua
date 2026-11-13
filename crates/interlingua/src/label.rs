//! Security labels: the confidentiality / integrity / availability triad.
//!
//! Every message carries a FIPS 199 security category, one potential-impact
//! level per security objective, plus a set of compartments (need-to-know
//! categories). CNSSI No. 1253 uses the same three objectives for national
//! security systems. FIPS 199 allows "not applicable" only for the
//! confidentiality of public information, so integrity and availability are at
//! least `low`.
//!
//! Text form: `conf=moderate integ=high avail=low comp=ops,tt-c`
//! CBOR form: `[conf, integ, avail, [compartment, …]]`, impacts as
//! 0 = n/a, 1 = low, 2 = moderate, 3 = high, compartments sorted and unique.

use std::collections::BTreeSet;
use std::fmt;

use crate::cbor::Value;
use crate::error::Error;
use crate::ident;

/// Most compartments on one label.
pub const MAX_COMPARTMENTS: usize = 16;

/// FIPS 199 potential impact, ordered `NotApplicable < Low < Moderate < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Impact {
    /// Not applicable (confidentiality of public information only).
    NotApplicable = 0,
    /// Limited adverse effect.
    Low = 1,
    /// Serious adverse effect.
    Moderate = 2,
    /// Severe or catastrophic adverse effect.
    High = 3,
}

impl Impact {
    /// Parse `n/a`, `low`, `moderate` or `high`.
    ///
    /// # Errors
    /// [`Error::Label`] for anything else.
    pub fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "n/a" => Ok(Self::NotApplicable),
            "low" => Ok(Self::Low),
            "moderate" => Ok(Self::Moderate),
            "high" => Ok(Self::High),
            _ => Err(Error::Label("impact must be n/a, low, moderate or high")),
        }
    }

    /// The impact for a wire code.
    ///
    /// # Errors
    /// [`Error::Label`] for a code above 3.
    pub fn from_code(code: u64) -> Result<Self, Error> {
        match code {
            0 => Ok(Self::NotApplicable),
            1 => Ok(Self::Low),
            2 => Ok(Self::Moderate),
            3 => Ok(Self::High),
            _ => Err(Error::Label("impact code must be 0-3")),
        }
    }

    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u64 {
        self as u64
    }

    /// The text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "n/a",
            Self::Low => "low",
            Self::Moderate => "moderate",
            Self::High => "high",
        }
    }
}

impl fmt::Display for Impact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A message's security category and compartments.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Label {
    /// Confidentiality impact.
    pub confidentiality: Impact,
    /// Integrity impact (at least `Low`).
    pub integrity: Impact,
    /// Availability impact (at least `Low`).
    pub availability: Impact,
    /// Need-to-know compartments.
    pub compartments: BTreeSet<String>,
}

impl Label {
    /// A label after checking the FIPS 199 and compartment rules.
    ///
    /// # Errors
    /// [`Error::Label`] or [`Error::Identifier`] if a rule is broken.
    pub fn new(
        confidentiality: Impact,
        integrity: Impact,
        availability: Impact,
        compartments: BTreeSet<String>,
    ) -> Result<Self, Error> {
        let label = Self {
            confidentiality,
            integrity,
            availability,
            compartments,
        };
        label.validate()?;
        Ok(label)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.integrity == Impact::NotApplicable || self.availability == Impact::NotApplicable {
            return Err(Error::Label(
                "integrity and availability impacts are at least low (FIPS 199)",
            ));
        }
        if self.compartments.len() > MAX_COMPARTMENTS {
            return Err(Error::Label("more than 16 compartments"));
        }
        self.compartments
            .iter()
            .try_for_each(|c| ident::compartment(c))
    }

    /// Parse the text form, e.g. `conf=moderate integ=high avail=low comp=ops,tt-c`.
    /// The three impacts are required; `comp` is optional; order is free.
    ///
    /// # Errors
    /// [`Error::Label`] or [`Error::Identifier`].
    pub fn parse(text: &str) -> Result<Self, Error> {
        let (mut conf, mut integ, mut avail, mut comp) = (None, None, None, None);
        for token in text.split_ascii_whitespace() {
            let (key, value) = token
                .split_once('=')
                .ok_or(Error::Label("label terms are key=value"))?;
            let slot = match key {
                "conf" => &mut conf,
                "integ" => &mut integ,
                "avail" => &mut avail,
                "comp" => &mut comp,
                _ => return Err(Error::Label("label keys are conf, integ, avail and comp")),
            };
            if slot.replace(value).is_some() {
                return Err(Error::Label("a label key appears twice"));
            }
        }
        fn need(v: Option<&str>) -> Result<&str, Error> {
            v.ok_or(Error::Label("conf, integ and avail are all required"))
        }
        let mut compartments = BTreeSet::new();
        if let Some(list) = comp {
            for c in list.split(',') {
                ident::compartment(c)?;
                if !compartments.insert(c.to_owned()) {
                    return Err(Error::Label("a compartment appears twice"));
                }
            }
        }
        Self::new(
            Impact::parse(need(conf)?)?,
            Impact::parse(need(integ)?)?,
            Impact::parse(need(avail)?)?,
            compartments,
        )
    }

    /// The CBOR form.
    #[must_use]
    pub fn to_cbor(&self) -> Value {
        Value::Array(vec![
            Value::Unsigned(self.confidentiality.code()),
            Value::Unsigned(self.integrity.code()),
            Value::Unsigned(self.availability.code()),
            Value::Array(self.compartments.iter().cloned().map(Value::Text).collect()),
        ])
    }

    /// Parse the CBOR form, requiring compartments sorted and unique.
    ///
    /// # Errors
    /// [`Error::Schema`], [`Error::Label`] or [`Error::Identifier`].
    pub fn from_cbor(value: &Value) -> Result<Self, Error> {
        let items = value
            .as_array()
            .ok_or(Error::Schema("label must be an array"))?;
        let [c, i, a, comp] = items else {
            return Err(Error::Schema("label must have four elements"));
        };
        let impact = |v: &Value| {
            v.as_u64()
                .ok_or(Error::Schema("impact must be an unsigned integer"))
                .and_then(Impact::from_code)
        };
        let list = comp
            .as_array()
            .ok_or(Error::Schema("compartments must be an array"))?;
        let mut compartments = BTreeSet::new();
        let mut previous: Option<&str> = None;
        for entry in list {
            let name = entry
                .as_text()
                .ok_or(Error::Schema("compartment must be text"))?;
            if previous.is_some_and(|p| p >= name) {
                return Err(Error::Label("compartments must be sorted and unique"));
            }
            previous = Some(name);
            compartments.insert(name.to_owned());
        }
        Self::new(impact(c)?, impact(i)?, impact(a)?, compartments)
    }

    /// Whether `self`'s compartments include all of `other`'s.
    #[must_use]
    pub fn covers_compartments(&self, compartments: &BTreeSet<String>) -> bool {
        compartments.is_subset(&self.compartments)
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "conf={} integ={} avail={}",
            self.confidentiality, self.integrity, self.availability
        )?;
        if !self.compartments.is_empty() {
            let list: Vec<&str> = self.compartments.iter().map(String::as_str).collect();
            write!(f, " comp={}", list.join(","))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trip_and_rules() {
        let l = Label::parse("comp=tt-c,ops avail=low integ=high conf=moderate").unwrap();
        assert_eq!(
            l.to_string(),
            "conf=moderate integ=high avail=low comp=ops,tt-c"
        );
        assert_eq!(Label::from_cbor(&l.to_cbor()).unwrap(), l);
        assert!(Label::parse("conf=n/a integ=low avail=low").is_ok());
        assert!(Label::parse("conf=low integ=n/a avail=low").is_err());
        assert!(Label::parse("conf=low integ=low").is_err());
        assert!(Label::parse("conf=low integ=low avail=low conf=high").is_err());
        assert!(Label::parse("conf=low integ=low avail=low comp=a,a").is_err());
        assert!(Label::parse("conf=secret integ=low avail=low").is_err());
    }

    #[test]
    fn cbor_compartments_must_be_canonical() {
        let unsorted = Value::Array(vec![
            Value::Unsigned(1),
            Value::Unsigned(1),
            Value::Unsigned(1),
            Value::Array(vec![Value::Text("b".into()), Value::Text("a".into())]),
        ]);
        assert!(Label::from_cbor(&unsorted).is_err());
    }
}
