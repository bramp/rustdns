mod display;
mod dns;
mod errors;
mod io;
pub mod resource;
pub mod types;

#[macro_use]
extern crate num_derive;

// TODO Package level documentation!

pub use crate::types::*;

// Pull up the various types that should be on the front page of the docs.
#[doc(inline)]
pub use crate::types::Extension;
#[doc(inline)]
pub use crate::types::Message;
#[doc(inline)]
pub use crate::types::Question;
#[doc(inline)]
pub use crate::types::Record;

#[doc(inline)]
pub use crate::types::Class;

#[doc(inline)]
pub use crate::types::Type;
