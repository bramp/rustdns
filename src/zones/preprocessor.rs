// TODO Use https://github.com/Nadrieril/pest_consume

extern crate pest;

use pest::error::Error;
use pest::iterators::Pair;
use pest::Parser;
use std::result;

#[derive(Parser)]
#[grammar = "zones/preprocessor.pest"]
pub struct ZonePreprocessor;

type Result<T> = result::Result<T, Error<Rule>>;

fn parse_tokens(pair: Pair<Rule>) -> Result<String> {
    assert_eq!(pair.as_rule(), Rule::tokens);

    let mut result = String::new();
    let mut opens = 0;

    for pair in pair.into_inner() {
        match pair.as_rule() {
            Rule::open => {
                opens += 1;
                result.push_str(pair.as_str());
            }
            Rule::close => {
                opens -= 1;
                result.push_str(pair.as_str());
            }
            Rule::newline | Rule::comment => {
                if opens > 0 {
                    // Replace newlines or comments with spaces
                    for _i in 0..pair.as_str().len() {
                        result.push(' ');
                    }
                } else {
                    result.push_str(pair.as_str());
                }
            }
            _ => result.push_str(pair.as_str()),
        }
    }

    Ok(result)
}

/// Preprocess the input to handle braces. Specifically
/// ( and ) allow a record to span multiple lines, so this
/// replaces new lines with spaces when they are within braces.
pub(crate) fn preprocess(input: &str) -> Result<String> {
    let mut result = String::new();
    let file = ZonePreprocessor::parse(Rule::file, input)?.next().unwrap();
    for pair in file.into_inner() {
        match pair.as_rule() {
            Rule::tokens => result.push_str(&parse_tokens(pair)?),
            Rule::EOI => (), // Nothing
            _ => unreachable!("Unexpected rule: {:?}", pair.as_rule()),
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // Test Full files
    #[test]
    fn test_preprocessor() {
        let tests = vec![
            // Examples from https://www.nlnetlabs.nl/documentation/nsd/grammar-for-dns-zone-files/
            ("SOA ( 1 2 3 4 5 6 )", "SOA ( 1 2 3 4 5 6 )"),
            (
                "SOA ( 1 2 ) ( 3 4 ) ( 5 ) ( 6 )\nA 127.0.0.1",
                "SOA ( 1 2 ) ( 3 4 ) ( 5 ) ( 6 )\nA 127.0.0.1",
            ),
            (
                "SOA    soa    soa    ( 1\n2\n3\n4\n5\n6)",
                "SOA    soa    soa    ( 1 2 3 4 5 6)",
            ),
            (
                // Comments are handled correctly
                "SOA ; blah\nA 127.0.0.1",
                "SOA ; blah\nA 127.0.0.1",
            ),
            (
                // Comments are removed when in a '('
                "SOA (; blah\nA 127.0.0.1)",
                "SOA (       A 127.0.0.1)",
            ),
            (
                // '(' within a comment shouldn't change the parsing
                "SOA ; ( blah\nA 127.0.0.1",
                "SOA ; ( blah\nA 127.0.0.1",
            ),
        ];

        for (input, want) in tests {
            match preprocess(input) {
                Ok(got) => assert_eq!(got, want, "incorrect result for '{}'", input),
                Err(err) => panic!("'{}' failed:\n{}", input, err),
            }
        }
    }
}
