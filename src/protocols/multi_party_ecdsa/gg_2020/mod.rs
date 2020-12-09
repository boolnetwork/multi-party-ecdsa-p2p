/*
    Multi-party ECDSA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

pub mod blame;
pub mod orchestrate;
pub mod party_i;
pub mod orchestrate_blame;
use serde::{Deserialize, Serialize};
#[cfg(test)]
mod test;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ErrorType {
    error_type: String,
    bad_actors: Vec<usize>,
}

impl ErrorType {
    pub fn new(error_type: String, bad_actors: Vec<usize>) -> Self {
        ErrorType {
            error_type,
            bad_actors
        }
    }

    pub fn error_type(&self) -> String {
        self.error_type.clone()
    }

    pub fn bad_actors(&self) -> Vec<usize> {
        self.bad_actors.clone()
    }

    pub fn set_error_type(&mut self, error_type: String) {
        self.error_type = error_type;
    }

    pub fn set_bad_actores(&mut self, bad_actors: Vec<usize>) {
        self.bad_actors = bad_actors;
    }
}
