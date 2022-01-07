use crate::zones::parser::Rule;
use crate::zones::parser::ZoneParser;
/// TODO Document
// TODO https://github.com/Badcow/DNS-Parser has a nice custom format extension. Perhaps include?
use crate::zones::preprocessor::preprocess;
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

extern crate pest;

/// A Zone File. This is the unprocessed version of the zone file
/// where domains such as "@" have not yet been resolved, and fields
/// are optional. To turn this into [`Vec<rustdns::Record>`] call
/// [`process`].
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
    pub fn new(mut origin: Option<String>, entries: Vec<Entry>) -> File {
        if let Some(domain) = origin {
            if let Some(domain) = domain.strip_suffix('.') {
                origin = Some(domain.to_owned())
            } else {
                panic!("TODO Origin wasn't a absolute domain");
            }
        }

        File { origin, entries }
    }
}

impl FromStr for File {
    type Err = pest_consume::Error<Rule>;

    /// Parse a full zone file.
    ///
    /// ```
    /// use rustdns::Resource;
    /// use rustdns::zones::{File, Entry, Record};
    /// use std::str::FromStr;
    ///
    /// let file = File::from_str("$ORIGIN example.com.\n www  A   192.0.2.1");
    /// assert_eq!(file, Ok(File::new(None, vec![
    ///   Entry::Origin("example.com.".to_string()),
    ///   Entry::Record(Record {
    ///     name: Some("www".to_string()),
    ///     ttl: None,
    ///     class: None,
    ///     resource: Resource::A("192.0.2.1".parse().unwrap()),
    ///   }),
    /// ])));
    /// ```
    fn from_str(input_str: &str) -> Result<Self, Self::Err> {
        let input_str = preprocess(input_str).unwrap(); // TODO

        let inputs = ZoneParser::parse(Rule::file, &input_str)?;
        let input = inputs.single()?;

        ZoneParser::file(input).map(|x| File::new(None, x))
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

/// Very similar to a [`rustdns::Record`] but allows for
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
    fn from_str(input_str: &str) -> Result<Self, Self::Err> {
        let inputs = ZoneParser::parse(Rule::single_record, input_str)?;
        let input = inputs.single()?;
        ZoneParser::single_record(input)
    }
}
