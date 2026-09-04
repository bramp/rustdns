/// TODO Document
// TODO https://github.com/Badcow/DNS-Parser has a nice custom format extension. Perhaps include?
use crate::zones::preprocessor::preprocess;
use crate::zones::parser::Rule;
use crate::zones::parser::ZoneParser;
use crate::Class;
use crate::Resource;
use pest_consume::Parser;
use std::str::FromStr;
use std::time::Duration;
use strum_macros::Display;

mod parser;
mod parser_tests;
mod preprocessor;
mod process;

pub use process::ProcessError;

/// A Zone File. This is the unprocessed version of the zone file
/// where domains such as "@" have not yet been resolved, and fields
/// are optional. To turn this into [`Vec<crate::Record>`] call
/// [`File::try_into_records`].
#[derive(Clone, Debug, PartialEq)]
pub struct File {
    /// The origin as defined when creating the Zone File. This is different than
    /// a origin set within the zone file.
    ///
    /// This should always be a absolute domain, but we don't need the dot on the end.
    pub origin: Option<String>,

    /// The list of Entries within the Zone File.
    pub entries: Vec<Entry>,
}

impl File {
    /// Creates a zone file, returning an error when the origin is not absolute.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::OriginNotAbsolute`] when `origin` is present but
    /// does not end in a root label (`.`).
    pub fn try_new(
        mut origin: Option<String>,
        entries: Vec<Entry>,
    ) -> Result<File, ProcessError> {
        if let Some(domain) = origin {
            if let Some(domain) = domain.strip_suffix('.') {
                origin = Some(domain.to_owned())
            } else {
                return Err(ProcessError::OriginNotAbsolute {
                    entry_index: 0,
                    origin: domain.to_string(),
                });
            }
        }

        Ok(File { origin, entries })
    }
}

impl FromStr for File {
    type Err = pest_consume::Error<Rule>;

    /// Parse a full zone file.
    ///
    /// # Errors
    ///
    /// Returns a Pest parsing error when the zone-file syntax is invalid.
    ///
    /// ```
    /// use rustdns::Resource;
    /// use rustdns::zones::{File, Entry, Record};
    /// use std::str::FromStr;
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let file = File::from_str("$ORIGIN example.com.\n www  A   192.0.2.1");
    /// assert_eq!(file, Ok(File::try_new(None, vec![
    ///   Entry::Origin("example.com.".to_string()),
    ///   Entry::Record(Record {
    ///     name: Some("www".to_string()),
    ///     ttl: None,
    ///     class: None,
    ///     resource: Resource::A("192.0.2.1".parse().unwrap()),
    ///   }),
    /// ])?));
    /// Ok(())
    /// }
    /// ```
    fn from_str(input_str: &str) -> Result<Self, Self::Err> {
        let input_str = preprocess(input_str).unwrap(); // TODO

        let inputs = ZoneParser::parse(Rule::file, &input_str)?;
        let input = inputs.single()?;
        let position = input.as_span().start_pos();

        ZoneParser::file(input).and_then(|x| File::try_new(None, x).map_err(|error| {
            pest_consume::Error::new_from_pos(
                pest::error::ErrorVariant::CustomError {
                    message: error.to_string(),
                },
                position,
            )
        }))
    }
}

/// Internal struct for capturing each entry.
#[derive(Clone, Debug, Display, PartialEq)]
pub enum Entry {
    Origin(String),
    TTL(Duration),
    // TODO support $INCLUDE
    Record(Record),
}

/// Very similar to a [`crate::Record`] but allows for
/// optional values. When parsing a full zone file
/// those options can be derived from previous entries.
// TODO Implement a Display to turn this back into Zone format.
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub name: Option<String>,
    pub ttl: Option<Duration>,
    pub class: Option<Class>,
    pub resource: Resource,
}

impl Default for Record {
    fn default() -> Self {
        Self {
            name: None,
            ttl: None,
            class: None,
            resource: Resource::ANY, // This is not really a good default, but it's atleast invalid.
        }
    }
}

impl FromStr for Record {
    type Err = pest_consume::Error<Rule>;

    /// Parse a single zone file resource record.
    ///
    /// For example:
    ///
    /// ```
    /// use rustdns::Resource;
    /// use rustdns::zones::Record;
    /// use std::str::FromStr;
    ///
    /// let record = Record::from_str("example.com.  A   192.0.2.1");
    /// assert_eq!(record, Ok(Record {
    ///   name: Some("example.com.".to_string()),
    ///   ttl: None,
    ///   class: None,
    ///   resource: Resource::A("192.0.2.1".parse().unwrap()),
    /// }));
    /// ```
    ///
    /// This function is mostly useful for test code, or quickly parsing a
    /// single record. Please prefer to use [`File::from_str`] to parse full files.
    ///
    /// # Errors
    ///
    /// Returns a Pest parsing error when the record syntax or resource data is invalid.
    fn from_str(input_str: &str) -> Result<Self, Self::Err> {
        let inputs = ZoneParser::parse(Rule::single_record, input_str)?;
        let input = inputs.single()?;
        ZoneParser::single_record(input)
    }
}
