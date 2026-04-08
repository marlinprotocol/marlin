use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use aws_sdk_ec2::types::{DomainType, InstanceType, ResourceType};
use aws_types::region::Region;
use base64::{Engine, prelude::BASE64_STANDARD};
use ssh_key::{Algorithm, LineEnding, PrivateKey, rand_core::OsRng};
use tracing::{debug, info};
use whoami::username;

use crate::market::{InfraProvider, JobId};

// AWS backed infra provider
#[derive(Clone)]
pub struct Aws {
    clients: HashMap<String, aws_sdk_ec2::Client>,
    key_name: String,
    key_location: PathBuf,
    pubkey_location: PathBuf,
    whitelist: &'static [String],
    blacklist: &'static [String],
    rl_ips: HashMap<String, String>,
}

// Initialization
impl Aws {
    pub async fn new(
        aws_profile: String,
        regions: &[String],
        key_name: String,
        whitelist: &'static [String],
        blacklist: &'static [String],
    ) -> Result<Aws> {
        let mut clients = HashMap::<String, aws_sdk_ec2::Client>::with_capacity(regions.len());
        for region in regions {
            let config = aws_config::from_env()
                .profile_name(&aws_profile)
                .region(Region::new(region.clone()))
                .load()
                .await;
            clients.insert(region.clone(), aws_sdk_ec2::Client::new(&config));
        }

        let username = username().context("could not retrieve user name")?;
        let key_location = format!("/home/{username}/.ssh/{key_name}.pem").into();
        let pubkey_location = format!("/home/{username}/.ssh/{key_name}.pub").into();

        let mut aws = Aws {
            clients,
            key_name,
            key_location,
            pubkey_location,
            whitelist,
            blacklist,
            rl_ips: HashMap::new(),
        };

        for region in regions {
            let ip = aws.fetch_rate_limiter_ip(region).await?;
            aws.rl_ips.insert(region.clone(), ip);
        }

        Ok(aws)
    }

    fn client(&self, region: &str) -> &aws_sdk_ec2::Client {
        &self.clients[region]
    }
}

// Utility macros
macro_rules! filter {
    ($name:expr, $($value:expr),+ $(,)?) => {
        aws_sdk_ec2::types::Filter::builder()
            .name($name)
            $( .values($value) )+
            .build()
    };
}

macro_rules! tag_spec {
    // Matches the ResourceType, followed by key => value pairs
    ($resource_type:expr, $( $key:expr => $value:expr ),* $(,)? ) => {
        aws_sdk_ec2::types::TagSpecification::builder()
            .resource_type($resource_type)
            $(
                // Builds and attaches each tag in line
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key($key)
                        .value($value)
                        .build()
                )
            )*
            .build()
    };
}

// Key setup
impl Aws {
    pub async fn key_setup(&self, regions: &[String]) -> Result<()> {
        self.generate_key_pair()
            .context("Failed to generate key pair")?;

        for region in regions {
            let key_check = self
                .check_key_pair(region)
                .await
                .with_context(|| format!("Failed to check key pair in {region}"))?;

            if !key_check {
                self.import_key_pair(region)
                    .await
                    .with_context(|| format!("Failed to import key pair in {region}"))?;
            } else {
                info!(
                    region,
                    "Found existing keypair and pem file, skipping key setup"
                );
            }
        }

        Ok(())
    }

    fn generate_key_pair(&self) -> Result<()> {
        let priv_check = self.key_location.exists();
        let pub_check = self.pubkey_location.exists();

        if priv_check && pub_check {
            // both exist, we are done
            Ok(())
        } else if priv_check {
            // only private key exists, generate public key
            let private_key = PrivateKey::read_openssh_file(&self.key_location)
                .context("Failed to read private key file")?;

            private_key
                .public_key()
                .write_openssh_file(&self.pubkey_location)
                .context("Failed to write public key file")?;

            Ok(())
        } else if pub_check {
            // only public key exists, error out to avoid overwriting it
            Err(anyhow!(
                "Found public key file without corresponding private key file, exiting to prevent overwriting it"
            ))
        } else {
            // neither exist, generate private key and public key
            let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
                .context("Failed to generate private key")?;

            private_key
                .write_openssh_file(&self.key_location, LineEnding::default())
                .context("Failed to write private key file")?;

            private_key
                .public_key()
                .write_openssh_file(&self.pubkey_location)
                .context("Failed to write public key file")?;

            Ok(())
        }
    }

    async fn check_key_pair(&self, region: &str) -> Result<bool> {
        Ok(!self
            .client(region)
            .describe_key_pairs()
            .filters(filter!("key-name", &self.key_name))
            .send()
            .await
            .context("Failed to query key pairs")?
            .key_pairs()
            .is_empty())
    }

    async fn import_key_pair(&self, region: &str) -> Result<()> {
        let pubkey = std::fs::read(&self.pubkey_location).context("Failed to read pubkey file")?;

        self.client(region)
            .import_key_pair()
            .key_name(&self.key_name)
            .public_key_material(aws_sdk_ec2::primitives::Blob::new(pubkey))
            .send()
            .await
            .context("Failed to import key pair")?;

        Ok(())
    }
}

// Elastic IP
impl Aws {
    // returns (is_new, alloc_id, ip, assoc_id)
    async fn get_or_allocate_ip_for_job(
        &self,
        job: &JobId,
        region: &str,
    ) -> Result<(bool, String, String, Option<(String, String)>)> {
        if let Some((alloc_id, public_ip, association_id)) = self
            .get_ip_for_job(job, region)
            .await
            .context("could not get elastic ip for job")?
        {
            return Ok((false, alloc_id, public_ip, association_id));
        }

        let tags = tag_spec!(
            ResourceType::ElasticIp,
            "managedBy" => "marlin",
            "project" => "marlin-cvm",
            "jobId" => job.id.to_string(),
            "operator" => &job.operator,
            "chainID" => &job.chain,
            "contractAddress" => &job.contract,
        );

        let resp = self
            .client(region)
            .allocate_address()
            .domain(DomainType::Vpc)
            .tag_specifications(tags)
            .send()
            .await
            .context("could not allocate elastic ip")?;

        Ok((
            true,
            resp.allocation_id()
                .ok_or(anyhow!("could not parse allocation id"))?
                .to_string(),
            resp.public_ip()
                .ok_or(anyhow!("could not parse public ip"))?
                .to_string(),
            None,
        ))
    }

    // returns (ip, allocation_id, association_id) if it exists
    async fn get_ip_for_job(
        &self,
        job: &JobId,
        region: &str,
    ) -> Result<Option<(String, String, Option<(String, String)>)>> {
        let job_filter = filter!("tag:jobId", job.id.to_string());
        let operator_filter = filter!("tag:operator", &job.operator);
        let chain_filter = filter!("tag:chainID", &job.chain);
        let contract_filter = filter!("tag:contractAddress", &job.contract);

        let describe_addresses_output = self
            .client(region)
            .describe_addresses()
            .filters(job_filter)
            .filters(operator_filter)
            .filters(contract_filter)
            .filters(chain_filter)
            .send()
            .await
            .context("could not describe elastic ips")?;
        let Some(address) = describe_addresses_output
            // response parsing starts here
            .addresses()
            .first()
        else {
            return Ok(None);
        };

        Ok(Some((
            address
                .public_ip()
                .ok_or(anyhow!("could not parse public ip"))?
                .to_string(),
            address
                .allocation_id()
                .ok_or(anyhow!("could not parse allocation id"))?
                .to_string(),
            address
                .association_id()
                .map(String::from)
                .zip(address.instance_id().map(String::from)),
        )))
    }

    async fn associate_address(
        &self,
        instance_id: &str,
        alloc_id: &str,
        region: &str,
    ) -> Result<()> {
        self.client(region)
            .associate_address()
            .allocation_id(alloc_id)
            .instance_id(instance_id)
            .send()
            .await
            .context("could not associate elastic ip")?;
        Ok(())
    }

    async fn disassociate_address(&self, association_id: &str, region: &str) -> Result<()> {
        self.client(region)
            .disassociate_address()
            .association_id(association_id)
            .send()
            .await
            .context("could not disassociate elastic ip")?;
        Ok(())
    }

    async fn release_address(&self, alloc_id: &str, region: &str) -> Result<()> {
        self.client(region)
            .release_address()
            .allocation_id(alloc_id)
            .send()
            .await
            .context("could not release elastic ip")?;
        Ok(())
    }
}

// Rate limiter
impl Aws {
    async fn fetch_rate_limiter_ip(&self, region: &str) -> Result<String> {
        let project_filter = filter!("tag:project", "marlin-cvm");
        let type_filter = filter!("tag:type", "limiter");

        let describe_instances_output = self
            .client(region)
            .describe_instances()
            .filters(project_filter)
            .filters(type_filter)
            .send()
            .await
            .context("could not describe rate limit instances")?;
        let instance = describe_instances_output
            .reservations()
            .first()
            .ok_or(anyhow!("no reservations found"))?
            .instances()
            .first()
            .ok_or(anyhow!("no instances found"))?;

        let ip = instance
            .private_ip_address()
            .ok_or(anyhow!("could not parse instance ip"))?
            .to_string();

        Ok(ip)
    }

    fn get_rate_limiter_ip(&self, region: &str) -> Result<String> {
        self.rl_ips
            .get(region)
            .cloned()
            .ok_or_else(|| anyhow!("rate limiter ip not found for region"))
    }

    async fn add_rate_limiter(
        &self,
        _job: &JobId,
        _cvm_ip: &str,
        _rl_ip: &str,
        _bandwidth: u64, // in kbit/sec
    ) -> Result<()> {
        todo!("configure with http calls");
    }

    async fn remove_rate_limiter(&self, _job: &JobId, _cvm_ip: &str, _rl_ip: &str) -> Result<()> {
        todo!("configure with http calls");
    }
}

// Instances
impl Aws {
    // returns (instance_id, is_healthy, private_ip, ami)
    async fn get_job_instance(
        &self,
        job: &JobId,
        region: &str,
    ) -> Result<Option<(String, bool, String, String)>> {
        let job_filter = filter!("tag:jobId", job.id.to_string());
        let operator_filter = filter!("tag:operator", &job.operator);
        let chain_filter = filter!("tag:chainID", &job.chain);
        let contract_filter = filter!("tag:contractAddress", &job.contract);
        let state_filter = filter!(
            "instance-state-name",
            "pending",
            "running",
            "stopping",
            "stopped"
        );

        let res = self
            .client(region)
            .describe_instances()
            .filters(job_filter)
            .filters(operator_filter)
            .filters(contract_filter)
            .filters(chain_filter)
            .filters(state_filter)
            .send()
            .await
            .context("could not describe instances")?;
        // response parsing from here
        let reservations = res.reservations();

        if reservations.is_empty() {
            Ok(None)
        } else {
            let instance = reservations[0]
                .instances()
                .first()
                .ok_or(anyhow!("instance not found"))?;
            let state = instance
                .state()
                .ok_or(anyhow!("could not parse instance state"))?
                .name()
                .ok_or(anyhow!("could not parse instance state name"))?
                .as_str();
            Ok(Some((
                instance
                    .instance_id()
                    .ok_or(anyhow!("could not parse ip address"))?
                    .to_string(),
                state == "pending" || state == "running",
                instance
                    .private_ip_address()
                    .ok_or(anyhow!("could not parse private ip"))?
                    .to_string(),
                instance
                    .image_id()
                    .ok_or(anyhow!("could not parse image id"))?
                    .to_string(),
            )))
        }
    }

    // returns (instance id, private ip)
    async fn launch_instance(
        &self,
        job: &JobId,
        instance_type: InstanceType,
        region: &str,
        init_params: &[u8],
        image: &str,
    ) -> Result<(String, String)> {
        let tags = tag_spec!(
            ResourceType::Instance,
            "Name" => format!("JobRunner {}", job.id),
            "managedBy" => "marlin",
            "project" => "marlin-cvm",
            "jobId" => job.id.to_string(),
            "operator" => &job.operator,
            "chainID" => &job.chain,
            "contractAddress" => &job.contract,
        );

        let subnet = self
            .get_subnet(region)
            .await
            .context("could not get subnet")?;
        let sec_group = self
            .get_security_group(region)
            .await
            .context("could not get security group")?;
        let run_instances_response = self
            .client(region)
            .run_instances()
            .image_id(image)
            .instance_type(instance_type)
            .min_count(1)
            .max_count(1)
            .tag_specifications(tags)
            .security_group_ids(sec_group)
            .subnet_id(subnet)
            .user_data(BASE64_STANDARD.encode(init_params))
            .send()
            .await
            .context("could not run instance")?;
        let instance = run_instances_response
            // response parsing from here
            .instances()
            .first()
            .ok_or(anyhow!("no instance found"))?;

        let instance_id = instance
            .instance_id()
            .ok_or(anyhow!("could not parse instance id"))?
            .to_string();
        let private_ip = instance
            .private_ip_address()
            .ok_or(anyhow!("could not parse private ip"))?
            .to_string();

        Ok((instance_id, private_ip))
    }

    async fn terminate_instance(&self, instance_id: &str, region: &str) -> Result<()> {
        self.client(region)
            .terminate_instances()
            .instance_ids(instance_id)
            .force(true)
            .send()
            .await
            .context("could not terminate instance")?;

        Ok(())
    }

    async fn get_security_group(&self, region: &str) -> Result<String> {
        let project_filter = filter!("tag:project", "marlin-cvm");

        Ok(self
            .client(region)
            .describe_security_groups()
            .filters(project_filter)
            .send()
            .await
            .context("could not describe security groups")?
            // response parsing from here
            .security_groups()
            .first()
            .ok_or(anyhow!("no security group found"))?
            .group_id()
            .ok_or(anyhow!("could not parse group id"))?
            .to_string())
    }

    async fn get_subnet(&self, region: &str) -> Result<String> {
        let project_filter = filter!("tag:project", "marlin-cvm");
        let type_filter = filter!("tag:type", "cvm");

        Ok(self
            .client(region)
            .describe_subnets()
            .filters(type_filter)
            .filters(project_filter)
            .send()
            .await
            .context("could not describe subnets")?
            // response parsing from here
            .subnets()
            .first()
            .ok_or(anyhow!("no subnet found"))?
            .subnet_id()
            .ok_or(anyhow!("Could not parse subnet id"))?
            .to_string())
    }
}

// Spin up/down
//
// Spin up ordering:
// Launch instance
// Add rate limiting
// Allocate EIP
// Associate EIP
//
// Spin down ordering:
// Disassociate EIP
// Release EIP
// Remove rate limiting
// Terminate instance
impl Aws {
    // might be called when the job is not healthy
    // might be called when the job params change
    // basically do not assume anything about the existing state
    async fn spin_up_impl(
        &mut self,
        job: &JobId,
        instance_type: &str,
        region: &str,
        bandwidth: u64,
        image: &str,
        init_params: &[u8],
    ) -> Result<()> {
        // NOTE: should this be in market itself?
        if !whitelist_blacklist_check(image, self.whitelist, self.blacklist) {
            bail!("failed whitelist/blacklist check");
        }

        let (instance_id, cvm_ip) = 'block: {
            if let Some((instance_id, is_healthy, cvm_ip, cvm_image)) = self
                .get_job_instance(job, region)
                .await
                .context("failed to get job instance")?
            {
                // instance exists already
                if is_healthy && cvm_image == image {
                    // instance exists and is already running our desired ami
                    info!(instance_id, "Found existing instance");

                    break 'block (instance_id, cvm_ip);
                } else {
                    // instance unhealthy or not running our image
                    // terminate and launch new one later
                    info!(
                        instance_id,
                        cvm_image, "Found existing unhealthy/mismatched instance"
                    );

                    // retain the EIP to reuse during spin up
                    // still important to disassociate for bandwidth metering
                    self.spin_down_impl(job, region, false)
                        .await
                        .context("failed to terminate instance")?;
                }
            }

            // launch new
            let instance_type =
                InstanceType::from_str(instance_type).context("cannot parse instance type")?;
            self.launch_instance(job, instance_type, region, init_params, image)
                .await
                .context("could not launch instance")?
        };

        // at this point, we should have an instance with the right image

        let rl_ip = self
            .get_rate_limiter_ip(region)
            .context("failed to get rate limiter ip")?;

        // add rate limit config
        self.add_rate_limiter(job, &cvm_ip, &rl_ip, bandwidth)
            .await
            .context("failed to add rate limit")?;

        // get or allocate eip
        // it is possible eip was left over from post_release_eip above
        let (_, alloc_id, _, assoc) = self
            .get_or_allocate_ip_for_job(job, region)
            .await
            .context("error allocating ip address")?;

        // associate ip if needed
        if let Some((_, eip_instance_id)) = assoc
            && eip_instance_id == instance_id
        {
            // ip is already associated, do nothing
        } else {
            // (re)associate ip
            self.associate_address(&instance_id, &alloc_id, region)
                .await
                .context("could not associate ip address")?;
        }

        Ok(())
    }

    async fn spin_down_impl(&self, job: &JobId, region: &str, do_release: bool) -> Result<()> {
        // disassociate and release eip if needed
        if let Some((alloc_id, _, association)) = self
            .get_ip_for_job(job, region)
            .await
            .context("could not get elastic ip of job")?
        {
            if let Some((association_id, _)) = association {
                self.disassociate_address(&association_id, region)
                    .await
                    .context("could not disassociate address")?;
            }

            if do_release {
                self.release_address(&alloc_id, region)
                    .await
                    .context("could not release address")?;
            }
        }

        let Some((instance_id, _, cvm_ip, _)) = self
            .get_job_instance(job, region)
            .await
            .context("failed to get job instance")?
        else {
            // instance does not exist, we are done
            info!("Instance does not exist");
            return Ok(());
        };

        let rl_ip = self
            .get_rate_limiter_ip(region)
            .context("failed to get rate limiter ip")?;

        // remove rate limit
        self.remove_rate_limiter(job, &cvm_ip, &rl_ip)
            .await
            .context("failed to remove rate limit")?;

        // terminate
        self.terminate_instance(&instance_id, region)
            .await
            .context("failed to terminate instance")
    }
}

#[must_use]
fn whitelist_blacklist_check(image: &str, whitelist: &[String], blacklist: &[String]) -> bool {
    // check whitelist
    if !whitelist.is_empty() {
        debug!("Checking whitelist...");
        if whitelist.iter().any(|s| s == image) {
            debug!("ALLOWED!");
        } else {
            debug!("NOT ALLOWED!");
            return false;
        }
    }

    // check blacklist
    if !blacklist.is_empty() {
        debug!("Checking blacklist...");
        if blacklist.iter().any(|s| s == image) {
            debug!("NOT ALLOWED!");
            return false;
        } else {
            debug!("ALLOWED!");
        }
    }

    true
}

impl InfraProvider for Aws {
    async fn spin_up(
        &mut self,
        job: &JobId,
        instance_type: &str,
        region: &str,
        bandwidth: u64,
        image: &str,
        init_params: &[u8],
    ) -> Result<()> {
        self.spin_up_impl(job, instance_type, region, bandwidth, image, init_params)
            .await
            .context("could not spin up enclave")
    }

    async fn spin_down(&mut self, job: &JobId, region: &str) -> Result<()> {
        self.spin_down_impl(job, region, true)
            .await
            .context("could not spin down enclave")
    }

    async fn get_ip(&self, job: &JobId, region: &str) -> Result<String> {
        let Some((_, elastic_ip, association_id)) = self
            .get_ip_for_job(job, region)
            .await
            .context("could not get job elastic ip")?
        else {
            // not found
            bail!("IP not found");
        };

        if association_id.is_none() {
            // not associated
            bail!("IP not associated");
        }

        Ok(elastic_ip)
    }

    async fn check_enclave_running(&mut self, job: &JobId, region: &str) -> Result<bool> {
        if let Some((_, is_healthy, _, _)) = self
            .get_job_instance(job, region)
            .await
            .context("could not get instance id for job")?
        {
            return Ok(is_healthy);
        };

        Ok(false)
    }
}
