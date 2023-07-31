/*!
# Guiding Thought
> The inventor of a cryptosystem must not only find a means for
> rendering information unintelligible, he must use a process which
> is logical and reproducible at the receiving end. All of you know
> already that we use things cslled "keys" which absolutely
> determine the specific encryption process. It follows from what I
> have just said that we always produce at least two of them, one
> for. the sender. one for the recipient. Through its application,
> and only through its application, the recipient is able to
> reverse, unscramble, or otherwise undo the encryption process.
 **David G. Boak -- National Security Agency -- 1973**
!*/
pub mod cdc;
pub mod config;
pub mod gb;
pub mod kd;
pub mod pad;
pub mod rng;
pub mod tp;
pub mod xor;

pub use cdc::*;
