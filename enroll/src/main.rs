extern crate serde;
extern crate serde_json;
extern crate libgatekeeper_sys;
extern crate reqwest;

use std::env;
use clap::{App, Arg};
use libgatekeeper_sys::{Nfc, Realm};
use serde_json::json;
use std::time::Duration;
use std::thread;
use std::io;
use std::fmt;
use serde::{Serialize, Deserialize};
// use reqwest::blocking::Client;
use reqwest::StatusCode;
use reqwest::header::AUTHORIZATION;
use libgatekeeper_sys::NfcDevice;

#[derive(Debug)]
pub enum GatekeeperError {
    Unknown,
}

impl std::error::Error for GatekeeperError {}

impl fmt::Display for GatekeeperError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return f.write_str(match self {
            GatekeeperError::Unknown => "Haha ligma", // I'm going to regret this
        });
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct KeyCreated {
    // The device itself should have an ID:
    keyId: String,
    uid: String,

    // Each realm has it's own association:
    doorsId: String,
    drinkId: String,
    memberProjectsId: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct UserLookup {
    id: String,
    groups: Vec<String>,
    disabled: bool,
}

#[derive(Clone)]
struct RealmKeys {
    auth_key: String,
    read_key: String,
    update_key: String,
    public_key: String,
    private_key: String,

    slot_name: String,
    slot: u8,
}

struct Provisions {
    doors: RealmKeys,
    drink: RealmKeys,
    member_projects: RealmKeys,

    prefix: String,
    // Consistent always
    system_secret: String,
    token: String,
}

fn create_realm(keys: RealmKeys, association: String) -> Realm {
    return Realm::new(
        keys.slot, &keys.slot_name.clone(), &association,
        &keys.auth_key, &keys.read_key,
        &keys.update_key, &keys.public_key,
        &keys.private_key
    ).unwrap();
}

fn resolve_id(client: &reqwest::blocking::Client, prefix: String,
              token: String, username: String) -> Result<UserLookup, Box<dyn std::error::Error>> {
    let res = client.get(
        prefix + "/users/uuid-by-uid/" + &username.to_string()
    ).header(AUTHORIZATION, token).send()?;
    return match res.status() {
        StatusCode::OK => match res.json::<UserLookup>() {
            Ok(user) => Ok(user),
            Err(_) => Err(Box::new(GatekeeperError::Unknown)),
        },
        StatusCode::NOT_FOUND => {
            println!("User {} doesn't exist!", username);
            Err(Box::new(GatekeeperError::Unknown))
        },
        status => {
            println!("Couldn't lookup user {}! {:?}", username, status);
            Err(Box::new(GatekeeperError::Unknown))
        },
    };
}

fn check_uid(client: &reqwest::blocking::Client, prefix: String,
             token: String, association: String) -> Result<String, Box<dyn std::error::Error>> {
    let res = client.get(
        prefix + "/keys/by-association/" + &association.to_string()
    ).header(AUTHORIZATION, token).send()?;
    return match res.status() {
        StatusCode::OK => match res.json::<KeyCreated>() {
            Ok(key) => Ok(key.uid),
            Err(_) => Err(Box::new(GatekeeperError::Unknown)),
        },
        StatusCode::NOT_FOUND => {
            println!("Key {} doesn't exist!", association);
            Err(Box::new(GatekeeperError::Unknown))
        },
        status => {
            println!("Couldn't lookup key {}! {:?}", association, status);
            Err(Box::new(GatekeeperError::Unknown))
        },
    }
}

fn main() {
    dotenv::dotenv().ok();
    let matches = App::new("Gatekeeper Door")
        .version("0.1.0")
        .author("Steven Mirabito <steven@stevenmirabito.com>")
        .about("Door lock client software for the Gatekeeper access control system")
        .arg(Arg::with_name("DEVICE")
             .help("Device connection string (e.g. 'pn532_uart:/dev/ttyUSB0')")
             .required(true)
             .index(1))
        .get_matches();

    let conn_str = matches.value_of("DEVICE").unwrap().to_string();
    let mut nfc = Nfc::new().ok_or("failed to create NFC context").unwrap();
    let mut device = nfc.gatekeeper_device(conn_str).ok_or("failed to get gatekeeper device").unwrap();

    let client = reqwest::blocking::Client::new();

    let provisions = Provisions {
        doors: RealmKeys {
            slot: 0,
            slot_name: "Doors".to_string(),

            auth_key: env::var("GK_REALM_DOORS_AUTH_KEY").unwrap(),
            read_key: env::var("GK_REALM_DOORS_READ_KEY").unwrap(),
            update_key: env::var("GK_REALM_DOORS_UPDATE_KEY").unwrap(),
            public_key: env::var("GK_REALM_DOORS_PUBLIC_KEY").unwrap(),
            private_key: env::var("GK_REALM_DOORS_PRIVATE_KEY").unwrap()
        },
        drink: RealmKeys {
            slot: 1,
            slot_name: "Drink".to_string(),

            auth_key: env::var("GK_REALM_DRINK_AUTH_KEY").unwrap(),
            read_key: env::var("GK_REALM_DRINK_READ_KEY").unwrap(),
            update_key: env::var("GK_REALM_DRINK_UPDATE_KEY").unwrap(),
            public_key: env::var("GK_REALM_DRINK_PUBLIC_KEY").unwrap(),
            private_key: env::var("GK_REALM_DRINK_PRIVATE_KEY").unwrap()
        },
        member_projects: RealmKeys {
            slot: 2,
            slot_name: "Member Projects".to_string(),

            auth_key: env::var("GK_REALM_MEMBER_PROJECTS_AUTH_KEY").unwrap(),
            read_key: env::var("GK_REALM_MEMBER_PROJECTS_READ_KEY").unwrap(),
            update_key: env::var("GK_REALM_MEMBER_PROJECTS_UPDATE_KEY").unwrap(),
            public_key: env::var("GK_REALM_MEMBER_PROJECTS_PUBLIC_KEY").unwrap(),
            private_key: env::var("GK_REALM_MEMBER_PROJECTS_PRIVATE_KEY").unwrap()
        },

        // Constants
        system_secret: env::var("GK_SYSTEM_SECRET").unwrap_or("b00".to_string()),
        prefix: env::var("GK_HTTP_ENDPOINT").unwrap_or("http://localhost:3000".to_string()) + "/admin",
        token: env::var("GK_ADMIN_SECRETS").unwrap()
    };

    loop {
        // https://github.com/rust-lang/rust/issues/59015
        let mut username: String = "".to_string();
        println!("Enter username:");
        if let Ok(_) = io::stdin().read_line(&mut username) {
          if let Err(err) = create_tag(&client, &mut username, &provisions, &mut device) {
            eprintln!("Couldn't create tag for user! {:?}", err);
          }
        }
    }
}

fn create_tag(client: &reqwest::blocking::Client, username: &mut String, provisions: &Provisions, device: &mut NfcDevice) -> Result<(), Box<dyn std::error::Error>> {
    // Drop newline
    username.pop();

    let resolution = resolve_id(
        &client, provisions.prefix.clone(),
        provisions.token.clone(), username.clone()
    )?;
    let uuid = resolution.id;

    println!("Ok, enrolling {}", username);

    // Now we can ask for the key!
    println!("Ready to register for {}! Please scan a tag to enroll it", username);
    loop {
        let tag = device.first_tag();
        if let Some(mut tag) = tag {
            let uid = match tag.authenticate(
                &mut create_realm(
                    provisions.doors.clone(),
                    "".to_string()
                )
            ) {
                Ok(association) => check_uid(
                    &client, provisions.prefix.clone(),
                    provisions.token.clone(), association
                ).ok(),
                Err(_) => None,
            };

            // What...
            let uid_str = match &uid {
                Some(uid) => Some(uid.as_str()),
                None => None,
            };
            // let uid_str = Some("047b4e92d65c80");

            if let Some(uid_str) = uid_str {
                println!("Formatting tag with uid {}", uid_str);
            } else {
                println!("Formatting tag with no care for UID");
            }
            match tag.format(
                uid_str,
                Some(&provisions.system_secret.clone())
            ) {
                Ok(_) => {
                    println!("Formatted tag");
                },
                Err(err) => {
                    println!("Failed formatting tag: {:?}", err);
                    continue;
                }
            }

            let new_uid = match uid_str {
                Some(uid) => uid.to_string(),
                None => tag.get_uid().unwrap(),
            };

            println!("Formatted tag, now telling server about new key with uid {}!", new_uid.clone());

            // Now we can ask the server!
            // We unwrap here because pattern matching hell
            // + there's probably something very wrong at that point
            let res = client.put(provisions.prefix.clone() + "/keys")
                .json(&json!({
                    "userId": uuid,
                    "uid": new_uid.clone(),
                }))
                .header(AUTHORIZATION, provisions.token.clone()).send()?;
            let data = res.json::<KeyCreated>()?;

            let mut realms: Vec<&mut Realm> = Vec::new();

            let mut doors = create_realm(
                provisions.doors.clone(),
                data.doorsId.clone()
            );
            realms.push(&mut doors);
            let mut drink = create_realm(
                provisions.drink.clone(),
                data.drinkId.clone()
            );
            realms.push(&mut drink);
            let mut member_projects = create_realm(
                provisions.member_projects.clone(),
                data.memberProjectsId.clone()
            );
            realms.push(&mut member_projects);

            match tag.issue(&provisions.system_secret.clone(), uid_str, realms) {
                Ok(_) => {
                    let res_result = client.patch(
                        provisions.prefix.clone() + "/keys/" + &data.keyId
                    ).header(AUTHORIZATION, provisions.token.clone()).json(&json!({
                        "enabled": true
                    })).send();

                    match res_result {
                        Ok(res) => match res.status() {
                            StatusCode::NO_CONTENT =>
                                println!("Issued for {}!", username),
                            status => {
                                println!("Failed to associate key with user! {:?}", status);
                                continue;
                            }
                        },
                        Err(error) => {
                            println!("Failed to associate key with user! {:?}", error);
                            continue;
                        }
                    }
                    break;
                },
                Err(err) => {
                    println!("Failed issuing... {:?}", err);
                }
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
    return Ok(());
}
