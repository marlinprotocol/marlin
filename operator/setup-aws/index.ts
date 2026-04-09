import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import { ProtocolType } from "@pulumi/aws/ec2";

let tags = {
    manager: "pulumi",
    project: "marlin-cvm",
}

let regions: aws.Region[] = [
    "ap-south-1",
]

let providers: { [key: string]: aws.Provider } = {}
export let publicDNS: aws.route53.Zone;
let vpcs: { [key: string]: aws.ec2.Vpc } = {}
let subnets: { [key: string]: aws.ec2.Subnet } = {}
let igs: { [key: string]: aws.ec2.InternetGateway } = {}
let rts: { [key: string]: aws.ec2.RouteTable } = {}
let rtas: { [key: string]: aws.ec2.RouteTableAssociation } = {}
let sgs: { [key: string]: { [key: string]: aws.ec2.SecurityGroup } } = {}
let instances: { [key: string]: aws.ec2.Instance } = {}

regions.forEach((region, ridx) => {
    // provider
    providers[region] = new aws.Provider(region, {
        region: region,
        profile: new pulumi.Config("aws").get("profile"),
    })

    // keypair for limiter vm
    let keypair = new aws.ec2.KeyPair(`${tags.project}`, {
        keyName: `${tags.project}`,
        publicKey: new pulumi.Config().require("pubkey"),
    }, {
        provider: providers[region],
    })

    // vpcs
    vpcs[region] = new aws.ec2.Vpc(`${tags.project}-${region}-vpc`, {
        cidrBlock: `10.${ridx}.0.0/16`,
        enableDnsHostnames: true,
        enableDnsSupport: true,
        tags: { ...tags, ...{ Name: `${tags.project}` } },
    }, {
        provider: providers[region],
    })

    // cvm subnet
    subnets[`${region}-cvm`] = new aws.ec2.Subnet(`${tags.project}-${region}-cvm`, {
        cidrBlock: `10.${ridx}.0.0/17`,
        mapPublicIpOnLaunch: false,
        tags: { ...tags, ...{ type: "cvm", Name: `${tags.project}-cvm` } },
        vpcId: vpcs[region].id,
    }, {
        provider: providers[region],
    });

    // limiter subnet
    subnets[`${region}-rl`] = new aws.ec2.Subnet(`${tags.project}-${region}-rl`, {
        cidrBlock: `10.${ridx}.128.0/17`,
        mapPublicIpOnLaunch: false,
        tags: { ...tags, ...{ type: "limiter", Name: `${tags.project}-limiter` } },
        vpcId: vpcs[region].id,
    }, {
        provider: providers[region],
    });

    // internet gateway
    igs[region] = new aws.ec2.InternetGateway(`${tags.project}-${region}-ig`, {
        vpcId: vpcs[region].id,
        tags: { ...tags, ...{ Name: `${tags.project}` } },
    }, {
        provider: providers[region],
    });

    // igw route table
    rts[`${region}-igw`] = new aws.ec2.RouteTable(`${tags.project}-${region}-rt-igw`, {
        vpcId: vpcs[region].id,
        tags: { ...tags, ...{ Name: `${tags.project}-igw` } },
    }, {
        provider: providers[region],
    });

    // igw route table associations
    rtas[`${region}-igw`] = new aws.ec2.RouteTableAssociation(`${tags.project}-${region}-igw-rta`, {
        gatewayId: igs[region].id,
        routeTableId: rts[`${region}-igw`].id,
    }, {
        provider: providers[region],
    });

    // cvm route table
    rts[`${region}-cvm`] = new aws.ec2.RouteTable(`${tags.project}-${region}-rt-cvm`, {
        vpcId: vpcs[region].id,
        tags: { ...tags, ...{ Name: `${tags.project}-cvm` } },
    }, {
        provider: providers[region],
    });

    // cvm route table associations
    rtas[`${region}-cvm`] = new aws.ec2.RouteTableAssociation(`${tags.project}-${region}-cvm-rta`, {
        subnetId: subnets[`${region}-cvm`].id,
        routeTableId: rts[`${region}-cvm`].id,
    }, {
        provider: providers[region],
    });

    // limiter route table
    rts[`${region}-rl`] = new aws.ec2.RouteTable(`${tags.project}-${region}-rt-rl`, {
        vpcId: vpcs[region].id,
        tags: { ...tags, ...{ Name: `${tags.project}-rl` } },
    }, {
        provider: providers[region],
    });

    // limiter route table associations
    rtas[`${region}-rl`] = new aws.ec2.RouteTableAssociation(`${tags.project}-${region}-rl-rta`, {
        subnetId: subnets[`${region}-rl`].id,
        routeTableId: rts[`${region}-rl`].id,
    }, {
        provider: providers[region],
    });

    // security groups
    sgs[region] = {}
    // security group for the cvms
    sgs[region].cvm = new aws.ec2.SecurityGroup(`${tags.project}-${region}-cvm`, {
        vpcId: vpcs[region].id,
        egress: [{
            cidrBlocks: ['0.0.0.0/0'],
            fromPort: 0,
            toPort: 0,
            protocol: "-1",
        }],
        ingress: [{
            cidrBlocks: ['0.0.0.0/0'],
            fromPort: 0,
            toPort: 0,
            protocol: "-1",
        }],
        tags: { ...tags, ...{ Name: `${tags.project}-cvm` } },
    }, {
        provider: providers[region],
    });

    // security group for the control plane eni
    sgs[region].limiterControl = new aws.ec2.SecurityGroup(`${tags.project}-${region}-limiter-control`, {
        vpcId: vpcs[region].id,
        egress: [{
            cidrBlocks: ['0.0.0.0/0'],
            fromPort: 0,
            toPort: 0,
            protocol: ProtocolType.All,
        }],
        ingress: [{
            cidrBlocks: ['0.0.0.0/0'],
            fromPort: 22,
            toPort: 22,
            protocol: ProtocolType.TCP,
        }, {
            cidrBlocks: [],
            fromPort: 3000,
            toPort: 3000,
            protocol: ProtocolType.TCP,
        }],
        tags: { ...tags, ...{ Name: `${tags.project}-limiter-control` } },
    }, {
        provider: providers[region],
    });

    // security group for the data plane eni
    sgs[region].limiterData = new aws.ec2.SecurityGroup(`${tags.project}-${region}-limiter-data`, {
        vpcId: vpcs[region].id,
        egress: [{
            cidrBlocks: ['0.0.0.0/0'],
            fromPort: 0,
            toPort: 0,
            protocol: ProtocolType.All,
        }],
        ingress: [{
            cidrBlocks: ['0.0.0.0/0'],
            fromPort: 0,
            toPort: 0,
            protocol: ProtocolType.All,
        }],
        tags: { ...tags, ...{ Name: `${tags.project}-limiter-data` } },
    }, {
        provider: providers[region],
    });

    // limiter vm ami
    const ami = aws.ec2.getAmi({
        filters: [
            { name: "name", values: ["marlin/limiter-arm64-*"] },
        ],
        owners: ["self"],
        mostRecent: true,
    }, { provider: providers[region] }).then(ami => ami.id);

    // limiter instance
    instances[`${region}-rl`] = new aws.ec2.Instance(`${tags.project}-${region}-rl-instance`, {
        ami: ami,
        instanceType: "t4g.small",
        subnetId: subnets[`${region}-rl`].id,
        keyName: keypair.keyName,
        // control plane sg for the default eni
        securityGroups: [sgs[region].limiterControl.id],
        tags: { ...tags, ...{ type: "limiter", Name: `${tags.project}-limiter` } },
    }, {
        provider: providers[region],
    });

    // limiter eip
    new aws.ec2.Eip(`${tags.project}-${region}-rl-eip`, {
        networkInterface: instances[`${region}-rl`].primaryNetworkInterfaceId,
        domain: "vpc",
        tags: { ...tags, ...{ type: "limiter", Name: `${tags.project}-limiter` } },
    }, {
        provider: providers[region],
    });

    // data plane eni
    const eni = new aws.ec2.NetworkInterface(`${tags.project}-${region}-rl-dpeni`, {
        // disable for forwarding
        sourceDestCheck: false,
        subnetId: subnets[`${region}-rl`].id,
        securityGroups: [sgs[region].limiterData.id],
        tags: { ...tags, ...{ type: "limiter", Name: `${tags.project}-limiter` } },
    }, {
        provider: providers[region],
    });
    new aws.ec2.NetworkInterfaceAttachment(`${tags.project}-${region}-rl-dpenia`, {
        instanceId: instances[`${region}-rl`].id,
        deviceIndex: 1,
        networkInterfaceId: eni.id,
    }, {
        provider: providers[region],
    });

    // limiter internet route
    new aws.ec2.Route(`${tags.project}-${region}-rl-ig-route`, {
        routeTableId: rts[`${region}-rl`].id,
        destinationCidrBlock: "0.0.0.0/0",
        gatewayId: igs[region].id,
    }, {
        provider: providers[region],
    });

    // igw cvm subnet route
    new aws.ec2.Route(`${tags.project}-${region}-igw-cvm-route`, {
        routeTableId: rts[`${region}-igw`].id,
        destinationCidrBlock: `10.${ridx}.0.0/17`,
        networkInterfaceId: eni.id,
    }, {
        provider: providers[region],
    })

    // cvm internet route
    new aws.ec2.Route(`${tags.project}-${region}-cvm-ig-route`, {
        routeTableId: rts[`${region}-cvm`].id,
        destinationCidrBlock: "0.0.0.0/0",
        networkInterfaceId: eni.id,
    }, {
        provider: providers[region],
    })
})
