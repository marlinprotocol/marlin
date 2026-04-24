use std::collections::HashMap;

use risc0_build::{DockerOptionsBuilder, GuestOptionsBuilder};

fn main() {
    let docker_options = DockerOptionsBuilder::default().build().unwrap();
    let guest_options = GuestOptionsBuilder::default()
        .use_docker(docker_options)
        .build()
        .unwrap();
    let mut options = HashMap::new();
    options.insert("guest", guest_options);
    risc0_build::embed_methods_with_options(options);
}
