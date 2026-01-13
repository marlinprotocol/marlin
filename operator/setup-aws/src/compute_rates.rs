use std::{collections::HashMap, ops::Mul};

use anyhow::Result;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_ec2::types::InstanceTypeHypervisor;
use aws_sdk_pricing::types::{Filter, FilterType};
use clap::Parser;
use serde::Serialize;
use serde_json::Value;
use tokio::fs;
use tokio_stream::StreamExt;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

static REGIONS: [&str; 1] = ["ap-south-1"];

static FAMILIES: [&str; 36] = [
    "m5", "m5a", "m5n", "m5zn", "m6a", "m6g", "m6i", "m6in", "m7g", "m7a", "m7i", "m8g", //
    "c5", "c5a", "c5n", "c6a", "c6g", "c6gn", "c6i", "c6in", "c7g", "c7gn", "c7a", "c7i",
    "c8g", //
    "r5", "r5a", "r5n", "r6a", "r6g", "r6i", "r6in", "r7g", "r7a", "r7i", "r8g", //
];

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long, value_parser)]
    profile: String,
    #[clap(long, value_parser)]
    premium: usize,
    #[clap(long, value_parser)]
    output: String,
}

async fn run() -> Result<()> {
    let args = Args::parse();

    info!(?args.profile);

    let regional_rate_cards = tokio_stream::iter(
        REGIONS
            .iter()
            .map(|v| (v.to_string(), &args.profile, args.premium)),
    )
    .then(run_region)
    .collect::<Vec<_>>()
    .await;

    let rates_json = serde_json::to_string_pretty(
        &serde_json::to_value(
            REGIONS
                .iter()
                .zip(regional_rate_cards.iter())
                .map(|(region, rate_cards)| {
                    HashMap::from([
                        ("region", Value::String(region.to_string())),
                        (
                            "rate_cards",
                            Value::Array(
                                rate_cards
                                    .iter()
                                    .map(|r| serde_json::to_value(r).unwrap())
                                    .collect::<Vec<_>>(),
                            ),
                        ),
                    ])
                })
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    )
    .unwrap();

    fs::write(args.output, rates_json).await?;

    Ok(())
}

async fn run_region((region, profile, premium): (String, &String, usize)) -> Vec<RateCard> {
    info!("Processing {region}");

    let ec2_client = aws_sdk_ec2::Client::new(
        &aws_config::defaults(BehaviorVersion::latest())
            .profile_name(profile)
            .region(Region::new(region.clone()))
            .load()
            .await,
    );
    let pricing_client = aws_sdk_pricing::Client::new(
        &aws_config::defaults(BehaviorVersion::latest())
            .profile_name(profile)
            .region(Region::new("us-east-1"))
            .load()
            .await,
    );

    let instance_types = ec2_client
        .describe_instance_types()
        .into_paginator()
        .send()
        .try_collect()
        .await
        .unwrap()
        .iter()
        .flat_map(|v| v.instance_types().iter())
        .filter_map(|i| {
            if i.hypervisor() != Some(&InstanceTypeHypervisor::Nitro)
                || !FAMILIES.contains(
                    &i.instance_type()
                        .unwrap()
                        .to_string()
                        .split_once(".")
                        .unwrap()
                        .0,
                )
            {
                return None;
            }

            return Some((
                i.instance_type().unwrap().to_string(),
                i.processor_info().unwrap().supported_architectures()[0].to_string(),
            ));
        })
        .collect::<Vec<_>>();

    async fn fetch_rate_card(
        (instance_type, arch, pricing_client, premium, region): (
            &String,
            &String,
            &aws_sdk_pricing::Client,
            usize,
            &String,
        ),
    ) -> RateCard {
        info!("Processing {instance_type}");

        pricing_client
            .get_products()
            .service_code("AmazonEC2")
            .filters(
                Filter::builder()
                    .r#type(FilterType::TermMatch)
                    .field("instanceType")
                    .value(instance_type)
                    .build()
                    .unwrap(),
            )
            .filters(
                Filter::builder()
                    .r#type(FilterType::TermMatch)
                    .field("regionCode")
                    .value(region)
                    .build()
                    .unwrap(),
            )
            .filters(
                Filter::builder()
                    .r#type(FilterType::TermMatch)
                    .field("operatingSystem")
                    .value("Linux")
                    .build()
                    .unwrap(),
            )
            .filters(
                Filter::builder()
                    .r#type(FilterType::TermMatch)
                    .field("preInstalledSw")
                    .value("NA")
                    .build()
                    .unwrap(),
            )
            .filters(
                Filter::builder()
                    .r#type(FilterType::TermMatch)
                    .field("capacitystatus")
                    .value("Used")
                    .build()
                    .unwrap(),
            )
            .filters(
                Filter::builder()
                    .r#type(FilterType::TermMatch)
                    .field("tenancy")
                    .value("Dedicated")
                    .build()
                    .unwrap(),
            )
            .into_paginator()
            .send()
            .try_collect()
            .await
            .unwrap()
            .iter()
            .flat_map(|v| v.price_list().iter())
            .flat_map(|v| serde_json::from_str::<Value>(v).ok())
            .filter_map(|v| {
                let &Value::Object(ref on_demand) = &v["terms"]["OnDemand"] else {
                    return None;
                };
                let term = on_demand.values().next().unwrap();
                let &Value::Object(ref price_dimensions) = &term["priceDimensions"] else {
                    return None;
                };
                let Value::String(price_string) =
                    &price_dimensions.values().next().unwrap()["pricePerUnit"]["USD"]
                else {
                    return None;
                };

                let price = price_string.parse::<f64>().unwrap().mul(1e6) as u128;

                Some(RateCard {
                    instance: instance_type.into(),
                    min_rate: (price * (100 + premium as u128) * 10u128.pow(12) / 360000)
                        .to_string(),
                    cpu: v["product"]["attributes"]["vcpu"]
                        .as_str()
                        .unwrap()
                        .parse::<usize>()
                        .unwrap(),
                    memory: (v["product"]["attributes"]["memory"]
                        .as_str()
                        .unwrap()
                        .split_once(" ")
                        .unwrap()
                        .0
                        .parse::<f64>()
                        .unwrap()
                        * 1024.0) as usize,
                    arch: if arch == "x86_64" {
                        "amd64".into()
                    } else {
                        "arm64".into()
                    },
                })
            })
            .next()
            .unwrap()
    }

    let mut rates = tokio_stream::iter(
        instance_types
            .iter()
            .map(|(a, b)| (a, b, &pricing_client, premium, &region)),
    )
    .then(fetch_rate_card)
    .collect::<Vec<_>>()
    .await;
    rates.sort_by_key(|v| {
        v.instance.split_once(".").unwrap().0.to_string() + "." + &format!("{:04}", v.cpu)
    });
    rates
}

#[derive(Serialize, Debug)]
struct RateCard {
    instance: String,
    min_rate: String,
    cpu: usize,
    memory: usize,
    arch: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // seems messy, see if there is a better way
    let mut filter = EnvFilter::new("info,aws_config=warn");
    if let Ok(var) = std::env::var("RUST_LOG") {
        filter = filter.add_directive(var.parse()?);
    }
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(filter)
        .init();

    let _ = run().await.inspect_err(|e| error!(?e, "run error"));

    Ok(())
}
