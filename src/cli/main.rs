//! MMS command line client

use std::{
    fs::File,
    io,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::{Args, Parser, Subcommand};
use mms::{client::*, *};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Command line arguments
#[derive(Parser)]
#[clap(name = "mms-client")]
struct Cli {
    /// Enable debug logging
    #[arg(long, default_value = "false")]
    debug: bool,

    /// Enable TLS
    #[arg(long, default_value = "false")]
    tls: bool,

    /// Set TLS CA certificate
    #[arg(long, requires = "tls")]
    ca_cert: Option<PathBuf>,

    /// Set mTLS client certificate
    #[arg(long, requires = "tls", requires = "client_key")]
    client_cert: Option<PathBuf>,

    /// Set mTLS client key
    #[arg(long, requires = "tls", requires = "client_cert")]
    client_key: Option<PathBuf>,

    /// Set the FQDN of the server certificate (if different than 'host')
    #[arg(long, requires = "tls")]
    cert_domain: Option<String>,

    /// Server port
    #[arg(short, long, default_value = "102")]
    port: u16,

    /// Server hostname or IP address
    host: String,

    /// Operation
    #[clap(subcommand)]
    command: Commands,
}

/// Primary operation
#[derive(Subcommand)]
enum Commands {
    /// Identify
    Identify,
    /// Get Name List
    List(ListArgs),
    /// Read variable(s)
    Read(ReadArgs),
    /// Read a variable list
    ReadList(ReadListArgs),
    /// Write variable
    Write(WriteArgs),
}

/// Object Class
#[derive(Subcommand)]
#[repr(u8)]
enum ListType {
    /// Named variables
    Variable = ObjectClassValue::NamedVariable as u8,
    /// Scattered access
    ScatteredAccess = ObjectClassValue::ScatteredAccess as u8,
    /// Named variable lists
    VariableList = ObjectClassValue::NamedVariableList as u8,
    /// Named types
    Type = ObjectClassValue::NamedType as u8,
    /// Semaphores
    Semaphore = ObjectClassValue::Semaphore as u8,
    /// Event conditions
    EventCondition = ObjectClassValue::EventCondition as u8,
    /// Event actions
    EventAction = ObjectClassValue::EventAction as u8,
    /// Event enrollments
    EventEnrollment = ObjectClassValue::EventEnrollment as u8,
    /// Journals
    Journal = ObjectClassValue::Journal as u8,
    /// Domains
    Domain = ObjectClassValue::Domain as u8,
    /// Program invocations
    Program = ObjectClassValue::ProgramInvocation as u8,
    /// Operator stations
    Station = ObjectClassValue::OperatorStation as u8,
}

/// 'List' arguments
#[derive(Args)]
struct ListArgs {
    /// Specify a domain scope for the object
    #[clap(short, long)]
    domain: Option<String>,

    /// Object class
    #[clap(subcommand)]
    class: ListType,
}

/// 'Read' arguments
#[derive(Args)]
struct ReadArgs {
    /// Specify a domain scope for the object
    #[clap(short, long)]
    domain: Option<String>,

    /// Print data types
    #[clap(short, long)]
    types: bool,

    /// Variable names
    #[arg(required = true)]
    names: Vec<String>,
}

/// 'ReadList' arguments
#[derive(Args)]
struct ReadListArgs {
    /// Specify a domain scope for the object
    #[clap(short, long)]
    domain: Option<String>,

    /// Output data types
    #[clap(short, long)]
    types: bool,

    /// Variable list name
    #[arg(required = true)]
    name: String,
}

/// Variable Data for writing
#[derive(Clone, Subcommand)]
enum WriteData {
    Bool {
        val: bool,
    },
    BitString {
        val: Vec<u8>,
    },
    Integer {
        val: isize,
    },
    Unsigned {
        val: usize,
    },
    Float {
        val: f64,
    },
    Bytes {
        val: Vec<u8>,
    },
    String {
        val: String,
    },
    GeneralizedTime {
        val: chrono::DateTime<chrono::FixedOffset>,
    },
    BinaryTime {
        val: Vec<u8>,
    },
    #[allow(clippy::upper_case_acronyms)]
    BCD {
        val: isize,
    },
    BoolArray {
        val: Vec<u8>,
    },
    #[allow(clippy::upper_case_acronyms)]
    OID {
        val: String,
    },
    MMSString {
        val: String,
    },
}

/// 'Write' arguments
#[derive(Args)]
struct WriteArgs {
    /// Specify a domain scope for the object
    #[clap(short, long)]
    domain: Option<String>,

    /// Variable name
    name: String,

    #[clap(subcommand)]
    data: WriteData,
}

fn print_access_result(label: Option<&str>, res: &AccessResult, annotate_types: bool) {
    if let Some(label) = label {
        println!("{label}:");
    }

    // Indent if following a label
    let indent = label.iter().len();

    match res {
        AccessResult::success(data) => print_data(data, indent, annotate_types),
        AccessResult::failure(err) => {
            eprintln!(
                "failure: {:?}",
                DataAccessErrorValue::try_from(err.0).unwrap_or(DataAccessErrorValue::ObjectValueInvalid)
            );
        }
    }
}

// TODO should be able to get the CHOICE variant's string identifier from rasn.
// However, it must be looked up in the list of identifiers using the tag, and
// it is not clear to me how to get the tag from the generated enum.
fn data_type(data: &Data) -> &'static str {
    match data {
        Data::array(_) => "array",
        Data::structure(_) => "struct",
        Data::boolean(_) => "boolean",
        Data::bit_string(_) => "bit-string",
        Data::integer(_) => "integer",
        Data::unsigned(_) => "unsigned",
        Data::floating_point(_) => "floating-point",
        Data::octet_string(_) => "octet-string",
        Data::visible_string(_) => "visible-string",
        Data::generalized_time(_) => "generalized-string",
        Data::binary_time(_) => "binary-time",
        Data::bcd(_) => "bcd",
        Data::booleanArray(_) => "boolean-array",
        Data::objId(_) => "object-id",
        Data::mMSString(_) => "mms-string",
        _ => "???",
    }
}

fn print_data(data: &Data, indent: usize, annotate_types: bool) {
    let prefix = " ".repeat(indent * 2);
    let data_type = data_type(data);

    print!("{prefix}");

    match data {
        Data::array(seq) | Data::structure(seq) => {
            println!("{data_type}:");
            seq.iter().for_each(|data| print_data(data, indent + 1, annotate_types))
        }
        Data::boolean(val) => print!("{val}"),
        Data::bit_string(val) => print!("{val}"),
        Data::integer(val) => print!("{val}"),
        Data::unsigned(val) => print!("{val}"),
        Data::floating_point(val) => print!("{:x}", val.0), // TODO need encode/decode for MMS FloatingPoint
        Data::octet_string(val) => print!("{val:x}"),
        Data::visible_string(val) => print!("{val}"),
        Data::generalized_time(val) => print!("{val}"),
        Data::binary_time(val) => print!("{:x}", val.0), // TODO need encode/decode for MMS TimeOfDay
        Data::bcd(val) => print!("{val}"),
        Data::booleanArray(val) => print!("{val}"),
        Data::objId(val) => print!("{val}"),
        Data::mMSString(val) => print!("{}", val.0),
        _ => print!("???"),
    }

    if annotate_types && !matches!(data, Data::array(_) | Data::structure(_)) {
        print!("  [{data_type}]");
    }

    println!();
}

fn load_certs(pem_file: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(pem_file)?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::certs(&mut reader).collect::<io::Result<Vec<_>>>()
}

fn load_private_key(der_file: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(der_file)?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::private_key(&mut reader)
        .transpose()
        .unwrap_or(Err(io::Error::new(
            io::ErrorKind::NotFound,
            "File does not contain a private key",
        )))
}

fn make_tls_config(cli: &Cli) -> io::Result<TLSConfig> {
    use rustls_platform_verifier::BuilderVerifierExt;

    // Client config builder using the `rustls` default crypto provider
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

    // Load CA certs from a PEM file, if supplied, or fall-back to the system certificate store
    let builder = if let Some(ca_cert) = &cli.ca_cert {
        let mut root_store = rustls::RootCertStore::empty();
        let certs = load_certs(ca_cert)?;
        root_store.add_parsable_certificates(certs);
        builder.with_root_certificates(root_store)
    } else {
        builder.with_platform_verifier()
    };

    // Enable mTLS if client certs were supplied
    let config = if let (Some(cert_path), Some(key_path)) = (&cli.client_cert, &cli.client_key) {
        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?
    } else {
        builder.with_no_client_auth()
    };

    let config = TLSConfig::new(config);

    // Override default domain name
    if let Some(domain_name) = &cli.cert_domain {
        Ok(config.domain_name(domain_name.clone()))
    } else {
        Ok(config)
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.debug {
        env_logger::builder().filter_level(log::LevelFilter::Trace).init();
    }

    let builder = if cli.tls {
        Client::builder().use_tls(make_tls_config(&cli)?)
    } else {
        Client::builder()
    };

    let client = builder.connect(cli.host, cli.port).await?;

    match cli.command {
        Commands::Identify => {
            let resp = client.identify().await?;

            println!("vendor:   {}", resp.vendor_name.0);
            println!("model:    {}", resp.vendor_name.0);
            println!("revision: {}", resp.vendor_name.0);

            if let Some(syntaxes) = resp.list_of_abstract_syntaxes {
                println!("syntaxes:");
                for oid in syntaxes {
                    println!("          {oid}");
                }
            }
        }

        Commands::List(args) => {
            let scope = match args.domain {
                Some(domain) => GetNameListRequestObjectScope::domainSpecific(Identifier(
                    VisibleString::from_iso646_bytes(domain.as_bytes()).unwrap(),
                )),
                None => GetNameListRequestObjectScope::vmdSpecific(()),
            };

            let resp = client
                .get_name_list(ObjectClass::basicObjectClass(args.class as u8), scope)
                .await?;

            for Identifier(id) in resp {
                println!("{id}");
            }
        }

        Commands::Read(args) => {
            let multiple = args.names.len() > 1;

            let variables = args
                .names
                .iter()
                .map(|name| {
                    let object = match args.domain.as_ref() {
                        Some(domain) => ObjectName::domain_specific(ObjectNameDomainSpecific {
                            domain_id: Identifier(VisibleString::from_iso646_bytes(domain.as_bytes()).unwrap()),
                            item_id: Identifier(VisibleString::from_iso646_bytes(name.as_bytes()).unwrap()),
                        }),
                        None => ObjectName::vmd_specific(Identifier(
                            VisibleString::from_iso646_bytes(name.as_bytes()).unwrap(),
                        )),
                    };

                    AnonymousVariableAccessSpecificationListOfVariable {
                        variable_specification: VariableSpecification::name(object),
                        alternate_access: None,
                    }
                })
                .collect();

            let variable_list = VariableAccessSpecificationListOfVariable(variables);

            let resp = client
                .read(VariableAccessSpecification::listOfVariable(variable_list))
                .await?;

            for (name, res) in args.names.iter().zip(resp) {
                // Add label if multiple variables were requested
                let label = if multiple { Some(name.as_str()) } else { None };

                print_access_result(label, &res, args.types);
            }
        }

        Commands::ReadList(args) => {
            let object = match args.domain.as_ref() {
                Some(domain) => ObjectName::domain_specific(ObjectNameDomainSpecific {
                    domain_id: Identifier(VisibleString::from_iso646_bytes(domain.as_bytes()).unwrap()),
                    item_id: Identifier(VisibleString::from_iso646_bytes(args.name.as_bytes()).unwrap()),
                }),
                None => ObjectName::vmd_specific(Identifier(
                    VisibleString::from_iso646_bytes(args.name.as_bytes()).unwrap(),
                )),
            };

            let resp = client
                .read(VariableAccessSpecification::variableListName(object))
                .await?;

            for res in resp {
                print_access_result(None, &res, args.types);
            }
        }

        Commands::Write(args) => {
            let object = match args.domain.as_ref() {
                Some(domain) => ObjectName::domain_specific(ObjectNameDomainSpecific {
                    domain_id: Identifier(VisibleString::from_iso646_bytes(domain.as_bytes()).unwrap()),
                    item_id: Identifier(VisibleString::from_iso646_bytes(args.name.as_bytes()).unwrap()),
                }),
                None => ObjectName::vmd_specific(Identifier(
                    VisibleString::from_iso646_bytes(args.name.as_bytes()).unwrap(),
                )),
            };

            let variable = AnonymousVariableAccessSpecificationListOfVariable {
                variable_specification: VariableSpecification::name(object),
                alternate_access: None,
            };
            let variable_list = VariableAccessSpecificationListOfVariable(vec![variable]);

            let data = match args.data {
                WriteData::Bool { val } => Data::boolean(val),
                WriteData::BitString { val } => Data::bit_string(BitString::from_vec(val)),
                WriteData::Integer { val } => Data::integer(Integer::Primitive(val)),
                WriteData::Unsigned { val } => Data::unsigned(Integer::Primitive(val as isize)),
                WriteData::Float { .. } => todo!("implement encoder for MMS floating point"),
                WriteData::Bytes { val } => Data::octet_string(OctetString::from(val)),
                WriteData::String { val } => Data::visible_string(VisibleString::from_iso646_bytes(val.as_bytes())?),
                WriteData::GeneralizedTime { val } => Data::generalized_time(val),
                WriteData::BinaryTime { val } => Data::binary_time(TimeOfDay(OctetString::from(val))),
                WriteData::BCD { val } => Data::bcd(Integer::Primitive(val)),
                WriteData::BoolArray { val } => {
                    let mut bits = BitString::new();
                    val.iter().for_each(|bit| bits.push(*bit != 0));
                    Data::booleanArray(bits)
                }
                WriteData::OID { val } => Data::objId(
                    ObjectIdentifier::new(
                        val.split('.')
                            .map(|id| id.parse::<u32>().unwrap_or_default())
                            .collect::<Vec<_>>(),
                    )
                    .ok_or("invalid OID")?,
                ),
                WriteData::MMSString { val } => {
                    Data::mMSString(MMSString(VisibleString::from_iso646_bytes(val.as_bytes())?))
                }
            };

            let resp = client
                .write(VariableAccessSpecification::listOfVariable(variable_list), vec![data])
                .await?;

            if let Some(AnonymousWriteResponse::failure(err)) = resp.first() {
                eprintln!(
                    "failure: {:?}",
                    DataAccessErrorValue::try_from(err.0).unwrap_or(DataAccessErrorValue::ObjectValueInvalid)
                );
            }
        }
    }

    Ok(())
}
